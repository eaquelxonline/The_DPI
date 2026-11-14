// Freedom Network — JVM-side tests (no third-party test framework; run by the Gradle `coreTest` task).
//
// Exercises the real JNI boundary against the host build of Native/Core.rs, the Kotlin
// wire codec, the platform TLS prober against a local TLS server, and the Turkish text
// catalogue. All network activity is loopback-only.

package com.freedom.network

import com.sun.net.httpserver.HttpsConfigurator
import com.sun.net.httpserver.HttpsServer
import java.io.File
import java.io.FileInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.KeyStore
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import kotlin.random.Random
import kotlin.system.exitProcess

private var passed = 0
private val failures = ArrayList<String>()

private fun test(name: String, body: () -> Unit) {
    val start = System.nanoTime()
    try {
        body()
        passed++
        println("PASS  $name (${(System.nanoTime() - start) / 1_000_000} ms)")
    } catch (t: Throwable) {
        failures += name
        println("FAIL  $name: $t")
        t.printStackTrace(System.out)
    }
}

private fun expect(cond: Boolean, msg: () -> String) {
    if (!cond) throw AssertionError(msg())
}

private fun <T> eq(actual: T, expected: T, what: String) = expect(actual == expected) { "$what: expected <$expected> but was <$actual>" }

private inline fun <reified E : Throwable> throws(block: () -> Unit) {
    try {
        block()
    } catch (e: Throwable) {
        if (e is E) return
        throw AssertionError("expected ${E::class.simpleName}, got $e")
    }
    throw AssertionError("expected ${E::class.simpleName}, nothing thrown")
}

// ---------------------------------------------------------------- loopback fixtures

/** Minimal DNS responder: answers every A query with 127.0.0.1; other types with no data. */
class FakeDns : AutoCloseable {
    private val socket = DatagramSocket(0, InetAddress.getLoopbackAddress()).apply { soTimeout = 50 }
    private val stop = AtomicBoolean(false)
    val queries = AtomicInteger()
    val address: String get() = "127.0.0.1:${socket.localPort}"
    private val thread = Thread {
        val buf = ByteArray(1500)
        while (!stop.get()) {
            val p = DatagramPacket(buf, buf.size)
            try { socket.receive(p) } catch (_: SocketTimeoutException) { continue } catch (_: Exception) { break }
            queries.incrementAndGet()
            val q = buf.copyOf(p.length)
            var i = 12
            while (i < q.size && q[i].toInt() != 0) i += (q[i].toInt() and 0xFF) + 1
            if (i + 5 > q.size) continue
            val qtype = ((q[i + 1].toInt() and 0xFF) shl 8) or (q[i + 2].toInt() and 0xFF)
            val question = q.copyOfRange(12, i + 5)
            val a = qtype == 1
            val out = java.io.ByteArrayOutputStream()
            out.write(q, 0, 2)
            out.write(byteArrayOf(0x81.toByte(), 0x80.toByte(), 0, 1, 0, if (a) 1 else 0, 0, 0, 0, 0))
            out.write(question)
            if (a) out.write(byteArrayOf(0xC0.toByte(), 0x0C, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 127, 0, 0, 1))
            val r = out.toByteArray()
            socket.send(DatagramPacket(r, r.size, p.socketAddress))
        }
    }.apply { isDaemon = true; start() }

    override fun close() {
        stop.set(true)
        thread.join(2000)
        socket.close()
    }
}

/** Local TLS server using the build-generated, throwaway self-signed certificate for svc.test. */
class TlsServer(ks: KeyStore, password: CharArray) : AutoCloseable {
    private val server: SSLServerSocket
    private val stop = AtomicBoolean(false)
    val port: Int get() = server.localPort

    init {
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(ks, password)
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(kmf.keyManagers, null, null)
        server = ctx.serverSocketFactory.createServerSocket(0, 16, InetAddress.getLoopbackAddress()) as SSLServerSocket
        server.soTimeout = 100
        val params = server.sslParameters
        params.applicationProtocols = arrayOf("h2", "http/1.1")
        server.sslParameters = params
        Thread {
            while (!stop.get()) {
                val c = try { server.accept() as SSLSocket } catch (_: SocketTimeoutException) { continue } catch (_: Exception) { break }
                Thread {
                    c.use {
                        runCatching {
                            it.soTimeout = 2000
                            it.startHandshake()
                            it.inputStream.read()
                        }
                    }
                }.apply { isDaemon = true; start() }
            }
        }.apply { isDaemon = true; start() }
    }

    override fun close() {
        stop.set(true)
        server.close()
    }
}

private fun loopbackConnect(): (String, Int, Int) -> Socket = { _, port, timeout ->
    Socket().apply { connect(InetSocketAddress(InetAddress.getLoopbackAddress(), port), timeout) }
}

private fun testKeystore(): Pair<KeyStore, CharArray> {
    val path = System.getProperty("freedom.test.keystore") ?: error("freedom.test.keystore not set")
    val pw = (System.getProperty("freedom.test.keystore.password") ?: error("password not set")).toCharArray()
    val ks = KeyStore.getInstance("PKCS12")
    FileInputStream(File(path)).use { ks.load(it, pw) }
    return ks to pw
}

private fun strictDefaultSslSocketFactory(): javax.net.ssl.SSLSocketFactory {
    val defaultTmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
        init(null as KeyStore?)
    }
    val hasIssuers = defaultTmf.trustManagers
        .filterIsInstance<javax.net.ssl.X509TrustManager>()
        .any { it.acceptedIssuers.isNotEmpty() }
    if (hasIssuers) return SSLContext.getDefault().socketFactory

    // Stripped container fallback when JDK cacerts is missing: load system PEM CAs
    // (or generate a distinct unrelated throwaway CA) so PKIX strictly validates and rejects svc.test.
    val ks = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null, null) }
    val pem = File("/etc/ssl/certs/ca-certificates.crt")
    if (pem.exists()) {
        val cf = java.security.cert.CertificateFactory.getInstance("X.509")
        runCatching {
            pem.inputStream().use { inp ->
                cf.generateCertificates(inp).forEachIndexed { idx, cert ->
                    ks.setCertificateEntry("sys-ca-$idx", cert)
                }
            }
        }
    }
    if (ks.size() == 0) {
        val tmp = File(System.getProperty("java.io.tmpdir"), "freedom-unrelated-ca-${System.nanoTime()}.p12")
        try {
            val kt = File(System.getProperty("java.home"), "bin/keytool" + if (System.getProperty("os.name").startsWith("Windows")) ".exe" else "").absolutePath
            ProcessBuilder(
                kt, "-genkeypair", "-alias", "unrelated", "-keyalg", "EC", "-groupname", "secp256r1", "-validity", "2",
                "-dname", "CN=unrelated-ca.invalid", "-storetype", "PKCS12",
                "-keystore", tmp.absolutePath, "-storepass", "changeit", "-keypass", "changeit",
            ).redirectErrorStream(true).start().waitFor()
            FileInputStream(tmp).use { ks.load(it, "changeit".toCharArray()) }
        } finally {
            tmp.delete()
        }
    }
    val customTmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(ks) }
    return SSLContext.getInstance("TLS").apply { init(null, customTmf.trustManagers, null) }.socketFactory
}

private fun env(dns: String) = EnvironmentInfo(
    osName = "Windows", osVersion = "Windows 11 24H2", osBuild = 26100, arch = "x86_64",
    networkType = NetworkType.ETHERNET, interfaceName = "test0", dnsServers = listOf(dns),
    mtu = 1500, hasIpv4 = YES, hasIpv6 = NO, connected = YES, validated = YES,
)

/** Minimal DoH answer for a native-built query: echo ID/question, one A record, no EDNS. */
private fun dnsAnswer(q: ByteArray, addr: ByteArray): ByteArray {
    var i = 12
    while (q[i].toInt() != 0) i += (q[i].toInt() and 0xFF) + 1
    val question = q.copyOfRange(12, i + 5)
    val out = java.io.ByteArrayOutputStream()
    out.write(q, 0, 2)
    out.write(byteArrayOf(0x81.toByte(), 0x80.toByte(), 0, 1, 0, 1, 0, 0, 0, 0))
    out.write(question)
    out.write(byteArrayOf(0xC0.toByte(), 0x0C, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4))
    out.write(addr)
    return out.toByteArray()
}

private val fastConfig = EngineConfig(timeoutMs = 600, dnsSamples = 2, tcpSamples = 2, mtu = false, cooldownMs = 0)

// ---------------------------------------------------------------- tests

fun main() {
    println("Freedom Network JVM tests · java ${System.getProperty("java.version")} · ${System.getProperty("os.name")}")

    test("native library loads and API version matches") {
        expect(Native.available) { "load error: ${Native.loadError}" }
        eq(Native.apiVersion(), Native.EXPECTED_API, "api")
        eq(Native.engineVersion(), "1.0.0", "engine version")
    }

    test("wire codec roundtrip (Kotlin)") {
        val inner = Record().int(1, -5).text(2, "çğıöşü ✓")
        val r = Record().int(0, 0).int(1, Long.MAX_VALUE).int(1, Long.MIN_VALUE).text(3, "").record(4, inner).record(4, Record())
        val back = Wire.decode(Wire.encode(r))
        eq(back, r, "roundtrip")
        eq(back.ints(1), listOf(Long.MAX_VALUE, Long.MIN_VALUE), "ints")
        eq(back.records(4)[0].getText(2), "çğıöşü ✓", "nested text")
    }

    test("wire codec rejects malformed input") {
        val bad = listOf(
            byteArrayOf(), "XX\u0001".toByteArray(), "DP\u0002".toByteArray(),
            byteArrayOf(68, 80, 1, 0, 1, 0), byteArrayOf(68, 80, 1, 0, 1, 0, 0, 0, 2, 0, 0),
            byteArrayOf(68, 80, 1, 0, 9, 0, 0, 0, 0), byteArrayOf(68, 80, 1, 0, 2, 0, 0, 0, 2, -1, -2),
            byteArrayOf(68, 80, 1, 0, 1, -1, -1, -1, -1),
        )
        bad.forEach { b -> throws<WireException> { Wire.decode(b) } }
        throws<WireException> { Wire.decode(ByteArray(Wire.MAX_MESSAGE + 1)) }
        var deep = Record()
        repeat(Wire.MAX_DEPTH) { deep = Record().record(1, deep) }
        throws<WireException> { Wire.encode(deep) }
    }

    test("wire fuzz only raises WireException") {
        val rnd = Random(42)
        repeat(20_000) {
            val b = rnd.nextBytes(rnd.nextInt(64))
            if (b.size >= 3 && rnd.nextBoolean()) { b[0] = 68; b[1] = 80; b[2] = 1 }
            try { Wire.decode(b) } catch (_: WireException) { }
        }
    }

    test("UTF-8 truncation keeps code points intact") {
        eq(Wire.truncateUtf8("aş", 2), "a", "split 2-byte char")
        val long = "ş".repeat(Wire.MAX_TEXT)
        val t = Record().text(1, long).getText(1)!!
        expect(t.toByteArray().size <= Wire.MAX_TEXT && t.all { it == 'ş' }) { "bad truncation" }
    }

    test("Kotlin-encoded records are accepted by Rust and vice versa") {
        val h = Native.create(Wire.encode(fastConfig.toRecord()))
        try {
            eq(Native.setEnvironment(h, Wire.encode(env("127.0.0.1:9").toRecord())), Codes.OK, "setEnvironment")
            val det = Wire.decode(Native.detectEnvironment()!!)
            val os = System.getProperty("os.name").lowercase()
            eq(det.status?.toInt(), if (os.contains("windows")) Codes.OK else Codes.UNSUPPORTED, "detect status")
            expect(det.getText(Tags.Env.ARCH)!!.isNotEmpty()) { "arch" }
            eq(EnvironmentInfo.fromRecord(env("1.1.1.1").toRecord()), env("1.1.1.1"), "env roundtrip")
        } finally {
            Native.destroy(h)
        }
    }

    test("JNI error handling and handle lifecycle") {
        val h = Native.create(null)
        expect(h > 0) { "handle $h" }
        eq(Native.create(byteArrayOf(1, 2, 3)), Codes.WIRE.toLong(), "garbage config")
        eq(Native.setEnvironment(h, byteArrayOf(9)), Codes.WIRE, "garbage env")
        eq(Decode.evaluation(Native.evaluate(h)).status, Codes.NO_DATA, "evaluate before diagnose")
        eq(Decode.run(Native.diagnose(h, Wire.encode(Record()))).status, Codes.NO_ENVIRONMENT, "no environment")
        eq(Native.markApplied(h, 999), Codes.INVALID_ARGUMENT, "bad action")
        eq(Native.destroy(h), Codes.OK, "destroy")
        eq(Native.destroy(h), Codes.INVALID_HANDLE, "double destroy")
        for (bad in listOf(h, 0L, -1L, Long.MAX_VALUE)) {
            eq(Native.networkChanged(bad), Codes.INVALID_HANDLE, "networkChanged($bad)")
            eq(Decode.evaluation(Native.evaluate(bad)).status, Codes.INVALID_HANDLE, "evaluate($bad)")
            eq(Native.submitTls(bad, Wire.encode(Record())), Codes.INVALID_HANDLE, "submitTls($bad)")
        }
        val h2 = Native.create(null)
        expect(h2 > h) { "handles must never be reused" }
        Native.destroy(h2)
    }

    test("invalid targets are rejected with the offending input") {
        DiagnosticSession(fastConfig).use { s ->
            s.setEnvironment(env("127.0.0.1:9"))
            val r = s.diagnose(listOf("ok.test", "exa mple"), emptyList())
            eq(r.status, Codes.INVALID_ARGUMENT, "status")
            eq(r.invalid, "exa mple", "invalid echo")
            eq(s.diagnose((0..8).map { "h$it.test" }, emptyList()).status, Codes.LIMIT, "target limit")
        }
    }

    test("closed session refuses use") {
        val s = DiagnosticSession(fastConfig)
        s.close()
        s.close()
        throws<IllegalStateException> { s.evaluate() }
    }

    test("TLS prober: certificate failure is reported, never bypassed") {
        val (ks, pw) = testKeystore()
        TlsServer(ks, pw).use { srv ->
            val strict = TlsProber(strictDefaultSslSocketFactory(), loopbackConnect())
            val r = strict.probe("svc.test", srv.port, 2000)
            eq(r.status, TlsStatus.CERTIFICATE, "untrusted self-signed")
        }
    }

    test("TLS prober: trusted server negotiates TLS 1.3 + ALPN h2") {
        val (ks, pw) = testKeystore()
        TlsServer(ks, pw).use { srv ->
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(ks) }
            val ctx = SSLContext.getInstance("TLS").apply { init(null, tmf.trustManagers, null) }
            val r = TlsProber(ctx.socketFactory, loopbackConnect()).probe("svc.test", srv.port, 2000)
            eq(r.status, TlsStatus.OK, "status")
            eq(r.version, "TLSv1.3", "version")
            eq(r.alpn, "h2", "alpn")
            // Hostname verification is enforced: wrong name fails even with a trusted cert.
            val wrong = TlsProber(ctx.socketFactory, loopbackConnect()).probe("other.test", srv.port, 2000)
            eq(wrong.status, TlsStatus.CERTIFICATE, "hostname mismatch")
        }
    }

    test("TLS prober: silent server times out within bound") {
        ServerSocket(0, 4, InetAddress.getLoopbackAddress()).use { ss ->
            val start = System.nanoTime()
            val r = TlsProber(strictDefaultSslSocketFactory(), loopbackConnect()).probe("svc.test", ss.localPort, 300)
            eq(r.status, TlsStatus.TIMEOUT, "status")
            expect((System.nanoTime() - start) / 1_000_000 < 3000) { "bounded" }
        }
    }

    test("end-to-end: native probes + platform TLS + evaluation") {
        val (ks, pw) = testKeystore()
        FakeDns().use { dns ->
            TlsServer(ks, pw).use { srv ->
                DiagnosticSession(fastConfig).use { s ->
                    eq(s.setEnvironment(env(dns.address)), Codes.OK, "env")
                    val target = listOf("svc.test:${srv.port}")
                    // 1) Default trust → certificate failure diagnosed.
                    val strict = TlsProber(strictDefaultSslSocketFactory(), loopbackConnect())
                    val r1 = s.run(target, emptyList(), strict)
                    eq(r1.run.status, Codes.OK, "run status")
                    val t = r1.run.targets.single()
                    eq(t.dnsStatus, 1, "dns ok")
                    eq(t.addresses, listOf("127.0.0.1"), "address")
                    expect(t.tcp4Ok > 0) { "tcp" }
                    eq(r1.tls.single().status, TlsStatus.CERTIFICATE, "tls")
                    val e1 = r1.evaluation!!
                    eq(e1.diagnoses.first().category, 8, "certificate diagnosis")
                    eq(e1.decision?.state, 1, "first sighting is only pending")
                    expect(dns.queries.get() >= 2) { "resolver sampled" }
                    // 2) Trusted → healthy, decision returns to Keep after debounce.
                    val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(ks) }
                    val ctx = SSLContext.getInstance("TLS").apply { init(null, tmf.trustManagers, null) }
                    val trusted = TlsProber(ctx.socketFactory, loopbackConnect())
                    val r2 = s.run(target, emptyList(), trusted)
                    eq(r2.run.targets.single().tlsVersion, "TLSv1.3", "tls version reported to native")
                    eq(r2.evaluation!!.diagnoses.first().category, 16, "healthy")
                    val text = Text.report(r2)
                    expect("Sorun tespit edilmedi" in text && "TLSv1.3" in text) { text }
                    // 3) Network change invalidates results.
                    eq(s.networkChanged(), Codes.OK, "network changed")
                    eq(s.evaluate().status, Codes.NO_DATA, "stale results discarded")
                }
            }
        }
    }

    test("wire codec Bytes kind roundtrip (Kotlin) and limits") {
        val r = Record().bytes(1, byteArrayOf(0, 1, -1, -128)).bytes(1, byteArrayOf()).text(2, "x")
        val back = Wire.decode(Wire.encode(r))
        eq(back, r, "roundtrip")
        expect(back.getBytes(1)!!.contentEquals(byteArrayOf(0, 1, -1, -128))) { "bytes" }
        eq(Record().bytes(1, ByteArray(Wire.MAX_BYTES + 10)).getBytes(1)!!.size, Wire.MAX_BYTES, "truncated")
    }

    test("DoH query is built natively (RFC 8484, ID 0) and endpoints must be https") {
        val q = Doh.query("Svc.Test")!!
        expect(q[0].toInt() == 0 && q[1].toInt() == 0) { "ID must be 0" }
        eq(Doh.query("exa mple"), null, "invalid name")
        expect(Doh.validEndpoint("https://dns.example/dns-query")) { "https ok" }
        expect(!Doh.validEndpoint("http://dns.example/dns-query")) { "cleartext rejected" }
        expect(!Doh.validEndpoint("https://")) { "no host rejected" }
    }

    test("DoH end-to-end: JDK HTTP client over local HTTPS, native validation, classification") {
        val (ks, pw) = testKeystore()
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(ks, pw) }
        val serverCtx = SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, null, null) }
        var mode = "ok"
        val https = HttpsServer.create(InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0)
        https.httpsConfigurator = HttpsConfigurator(serverCtx)
        https.createContext("/dns-query") { ex ->
            val q = ex.requestBody.readAllBytes()
            val (body, type) = if (mode == "ok") dnsAnswer(q, byteArrayOf(192.toByte(), 0, 2, 1)) to "application/dns-message"
            else "<html>login</html>".toByteArray() to "text/html"
            ex.responseHeaders.add("Content-Type", type)
            ex.sendResponseHeaders(200, body.size.toLong())
            ex.responseBody.use { it.write(body) }
        }
        https.start()
        try {
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(ks) }
            val clientCtx = SSLContext.getInstance("TLS").apply { init(null, tmf.trustManagers, null) }
            val client = JdkDohClient(clientCtx)
            val endpoint = "https://127.0.0.1:${https.address.port}/dns-query"
            FakeDns().use { dns ->
                TlsServer(ks, pw).use { srv ->
                    DiagnosticSession(fastConfig).use { s ->
                        s.setEnvironment(env(dns.address))
                        val target = listOf("svc.test:${srv.port}")
                        val r1 = s.run(target, emptyList(), null, client, listOf(endpoint, "http://cleartext.invalid/dns-query"))
                        val e1 = r1.encrypted.single()
                        eq(e1.transport, 1, "transport ok")
                        expect(e1.protocol == EncProtocol.DOH || e1.protocol == EncProtocol.DOH3) { "protocol ${e1.protocol}" }
                        val obs1 = r1.evaluation!!.diagnoses.flatMap { it.observations }.map { it.code }
                        expect(41 in obs1) { "encrypted DNS available advisory expected, got $obs1" }
                        expect("Şifreli DNS" in Text.report(r1)) { "report section" }
                        // A login page answering 200 text/html must never count as DNS.
                        mode = "html"
                        val r2 = s.run(target, emptyList(), null, client, listOf(endpoint))
                        eq(r2.encrypted.single().transport, 6, "non-DNS content")
                        val obs2 = r2.evaluation!!.diagnoses.flatMap { it.observations }.map { it.code }
                        expect(42 in obs2 && 41 !in obs2) { "failure advisory expected, got $obs2" }
                    }
                }
            }
        } finally {
            https.stop(0)
        }
    }

    test("system-wide snapshot: JNI call, platform status and Turkish rendering") {
        val snap = SystemSnapshot.capture()
        val windows = System.getProperty("os.name").lowercase().contains("windows")
        eq(snap.status, if (windows) Codes.OK else Codes.UNSUPPORTED, "status")
        expect(Text.system(snap).isNotEmpty()) { "render" }
        val synthetic = SystemSnapshot(
            Codes.OK, 10, 3, 1, 4, 0, 0, 2, 1,
            listOf(ProcessInfo(1200, "app.exe", 0, 4, 0, 0, 0, 4, listOf("203.0.113.1:443"))),
            listOf(Observation(1, "app.exe", listOf(4, 1200)), Observation(4, "", listOf(1))),
        )
        val text = Text.system(synthetic)
        expect("el sıkışmada takılı" in text && "app.exe" in text && "203.0.113.1:443" in text) { text }
        for (c in 1..Text.KNOWN_SYSTEM_FINDINGS) expect(!Text.systemFinding(Observation(c, "x", listOf(1, 2))).startsWith("Bulgu")) { "finding $c" }
    }

    test("concurrent use of one session is safe") {
        DiagnosticSession(fastConfig).use { s ->
            s.setEnvironment(env("127.0.0.1:9"))
            val errors = AtomicInteger()
            val go = CountDownLatch(1)
            val threads = (0 until 8).map {
                Thread {
                    go.await()
                    repeat(300) {
                        try {
                            s.evaluate(); s.networkChanged(); s.setEnvironment(env("127.0.0.1:9"))
                        } catch (e: Exception) {
                            errors.incrementAndGet()
                        }
                    }
                }.apply { start() }
            }
            go.countDown()
            threads.forEach { it.join() }
            eq(errors.get(), 0, "errors")
        }
    }

    test("stress: 5000 create/destroy cycles do not exhaust the registry") {
        repeat(5000) {
            val h = Native.create(null)
            expect(h > 0) { "create failed at $it: $h" }
            eq(Native.destroy(h), Codes.OK, "destroy")
        }
    }

    test("Turkish text catalogue covers every native code") {
        for (c in 1..Text.KNOWN_CATEGORIES) expect(!Text.category(c).startsWith("Kategori")) { "category $c" }
        for (a in 0..Text.KNOWN_ACTIONS) expect(!Text.actionTitle(a).startsWith("Eylem") && Text.actionDetail(a, 1400).isNotEmpty()) { "action $a" }
        for (o in 1..Text.KNOWN_OBSERVATIONS) expect(!Text.observation(Observation(o, "x", listOf(1, 2))).startsWith("Gözlem")) { "observation $o" }
        for (s in 0..7) expect(!Text.state(s).startsWith("Durum")) { "state $s" }
        for (s in 0..13) expect(!Text.status(s).startsWith("durum")) { "status $s" }
        for (m in 0..Text.KNOWN_DESYNC_MODES) expect(!Text.desyncMode(m).startsWith("Mod")) { "desyncMode $m" }
    }

    test("active DPI desync packet transformation and local proxy lifecycle over JNI") {
        DiagnosticSession(fastConfig).use { s ->
            val httpPayload = "GET / HTTP/1.1\r\nHost: blocked.example.com\r\n\r\n".toByteArray()
            val total = 40 + httpPayload.size
            val pkt = ByteArray(total)
            pkt[0] = 0x45.toByte()
            pkt[2] = ((total shr 8) and 0xff).toByte()
            pkt[3] = (total and 0xff).toByte()
            pkt[8] = 64
            pkt[9] = 6 // TCP
            pkt[12] = 10; pkt[13] = 0; pkt[14] = 0; pkt[15] = 1
            pkt[16] = 93.toByte(); pkt[17] = 184.toByte(); pkt[18] = 216.toByte(); pkt[19] = 34
            pkt[21] = 80
            pkt[23] = 80
            pkt[32] = 0x50.toByte()
            pkt[33] = 0x18.toByte()
            System.arraycopy(httpPayload, 0, pkt, 40, httpPayload.size)

            val res = s.desyncPacket(pkt, DesyncConfig(mode = DesyncMode.REALITY_VISION, fakeTtl = 4))
            eq(res.status, Codes.OK, "desync status")
            eq(res.mode, DesyncMode.REALITY_VISION, "reality_vision mode")
            eq(res.sni, "blocked.example.com", "extracted host")
            expect(!res.dropped && res.packets.size >= 3) { "expected REALITY + ML-KEM-768 decoy + disordered segments, got ${res.packets.size}" }

            val started = s.startProxy(DesyncConfig(mode = DesyncMode.REALITY_VISION, port = 0))
            eq(started.status, Codes.OK, "startProxy status")
            eq(started.mode, DesyncMode.REALITY_VISION, "startProxy mode")
            expect(started.active && started.port > 0) { "proxy active on port ${started.port}" }
            expect("FREEDOM NETWORK (YEREL DPI AŞMA)" in Text.proxyStatus(started) && "REALITY + ML-KEM-768" in Text.proxyStatus(started)) { "proxy Turkish status" }
            eq(s.stopProxy(), Codes.OK, "stopProxy")
            expect(!s.proxyStats().active) { "proxy stopped" }
        }
    }

    test("ServerManager: multi-profile personal servers, failover, quota, key rotation, and device revocation") {
        val mgr = ServerManager()
        val s1 = ServerProfile(
            id = "srv-01",
            name = "Sunucu 01",
            primaryEndpoint = "vpn.example.com:443",
            backupEndpoint = "backup01.example.com:443",
            coverDest = "dl.google.com",
            deviceId = "android-arm64-01",
            authKeyHex = "0102030405060708",
            latencyMs = 18,
            lossPct = 0,
            quotaBytes = 10_000,
        )
        val s2 = ServerProfile(
            id = "srv-02",
            name = "Sunucu 02",
            primaryEndpoint = "backup.example.com:443",
            coverDest = "www.cloudflare.com",
            deviceId = "windows-x64-01",
            authKeyHex = "aabbccddeeff0011",
            latencyMs = 34,
            lossPct = 1,
            quotaBytes = 50_000,
        )
        mgr.upsert(s1)
        mgr.upsert(s2)
        eq(mgr.list().size, 2, "2 profiles")
        val selected = mgr.select("srv-01")!!
        eq(selected.status, ServerStatus.CONNECTED, "srv-01 connected")
        eq(selected.activeEndpoint, "vpn.example.com:443", "primary endpoint")

        // Failover switches to backupEndpoint on srv-01
        val failedOver = mgr.triggerFailover("srv-01")!!
        eq(failedOver.status, ServerStatus.FAILOVER, "failover status")
        eq(failedOver.activeEndpoint, "backup01.example.com:443", "backup endpoint active")

        // Quota enforcement
        val afterTraffic = mgr.recordTraffic("srv-01", 10_500)!!
        eq(afterTraffic.status, ServerStatus.QUOTA_EXCEEDED, "quota exceeded")
        expect(!afterTraffic.quotaAvailable) { "quota must be exhausted" }

        // Device revocation switches active profile to srv-02
        val revoked = mgr.revokeDevice("srv-01")!!
        eq(revoked.status, ServerStatus.REVOKED, "revoked status")
        eq(mgr.activeProfileId, "srv-02", "auto-promoted to srv-02")

        // Key rotation restores device access
        val rotated = mgr.rotateDeviceKey("srv-01", "9988776655443322")!!
        expect(!rotated.revoked && rotated.authKeyHex == "9988776655443322") { "key rotated" }

        val rendered = Text.serverManager(mgr)
        expect("Sunucu 01" in rendered && "Sunucu 02" in rendered && "dl.google.com" in rendered) { rendered }
    }

    test("TunBridge end-to-end: Happy Eyeballs DoH3, tracker sinkhole, STUN leak guard, UDP NAT, and universal TCP Desync") {
        DiagnosticSession(fastConfig).use { s ->
            val appToBridgeIn = java.io.PipedInputStream(65536)
            val appToBridgeOut = java.io.PipedOutputStream(appToBridgeIn)
            val bridgeToAppIn = java.io.PipedInputStream(65536)
            val bridgeToAppOut = java.io.PipedOutputStream(bridgeToAppIn)

            val protectedTcpCount = AtomicInteger(0)
            val protectedUdpCount = AtomicInteger(0)

            val mockDoh = DohClient { _, body, _ ->
                // RFC 8484 requires ID=0 in DoH wire query
                expect(body.size >= 12 && body[0].toInt() == 0 && body[1].toInt() == 0) { "DoH query ID must be 0" }
                DohResponse(1, 500, EncProtocol.DOH3, dnsAnswer(body, byteArrayOf(104.toByte(), 16.toByte(), 132.toByte(), 229.toByte())))
            }

            fun readNextIpPacket(input: java.io.InputStream): ByteArray {
                val hdr = ByteArray(20)
                var read = 0
                while (read < 20) {
                    val n = input.read(hdr, read, 20 - read)
                    if (n < 0) error("EOF reading IPv4 header")
                    read += n
                }
                val totalLen = IpPackets.u16(hdr, 2)
                val full = ByteArray(totalLen)
                System.arraycopy(hdr, 0, full, 0, 20)
                while (read < totalLen) {
                    val n = input.read(full, read, totalLen - read)
                    if (n < 0) error("EOF reading IPv4 body")
                    read += n
                }
                return full
            }

            val clientIp = IpPackets.parseIpLiteral(TunBridge.VPN_CLIENT_IP)!!
            val vpnDnsIp = IpPackets.parseIpLiteral(TunBridge.VPN_DNS_IP)!!
            val loopbackIp = IpPackets.parseIpLiteral("127.0.0.1")!!

            TunBridge(
                session = s,
                tunInput = appToBridgeIn,
                tunOutput = bridgeToAppOut,
                protectSocket = { protectedTcpCount.incrementAndGet(); true },
                protectDatagram = { protectedUdpCount.incrementAndGet(); true },
                dohClient = mockDoh,
                dohEndpoints = listOf(
                    "https://1.1.1.1/dns-query",
                    "https://8.8.8.8/dns-query",
                ),
                strictKillSwitch = true,
                blockTrackers = true,
                hardenStunLeaks = true,
            ).use { bridge ->
                bridge.start()

                // 1) DNS-over-UDP (port 53) intercepted and resolved via Happy Eyeballs Encrypted DNS (DoH3)
                val rawDnsQuery = Doh.query("cloudflare.com")!!.also {
                    it[0] = 0xCA.toByte()
                    it[1] = 0xFE.toByte()
                }
                val dnsPkt = IpPackets.buildIpv4Udp(clientIp, vpnDnsIp, 53000, 53, rawDnsQuery)
                appToBridgeOut.write(dnsPkt)
                appToBridgeOut.flush()

                val dnsReplyPkt = readNextIpPacket(bridgeToAppIn)
                val dnsReplyUdp = IpPackets.parseUdp(dnsReplyPkt)!!
                eq(dnsReplyUdp.srcPort, 53, "DNS reply srcPort")
                eq(dnsReplyUdp.dstPort, 53000, "DNS reply dstPort")
                eq(dnsReplyUdp.payload[0], 0xCA.toByte(), "restored DNS ID hi")
                eq(dnsReplyUdp.payload[1], 0xFE.toByte(), "restored DNS ID lo")
                eq(bridge.dnsQueries.get(), 1, "dnsQueries counter")
                eq(bridge.dohResolved.get(), 1, "dohResolved counter")

                // 1b) Tracker/telemetry DNS sinkhole returns local NXDOMAIN without touching upstream DoH
                val trackerQuery = Doh.query("doubleclick.net")!!.also {
                    it[0] = 0xDE.toByte()
                    it[1] = 0xAD.toByte()
                }
                val trackerPkt = IpPackets.buildIpv4Udp(clientIp, vpnDnsIp, 53001, 53, trackerQuery)
                appToBridgeOut.write(trackerPkt)
                appToBridgeOut.flush()

                val trackerReplyPkt = readNextIpPacket(bridgeToAppIn)
                val trackerReplyUdp = IpPackets.parseUdp(trackerReplyPkt)!!
                eq(trackerReplyUdp.payload[0], 0xDE.toByte(), "tracker DNS ID hi")
                eq(trackerReplyUdp.payload[3].toInt() and 0x0F, 3, "tracker DNS RCODE=3 (NXDOMAIN)")
                eq(bridge.trackersBlocked.get(), 1, "trackersBlocked counter")
                eq(bridge.dohResolved.get(), 1, "tracker must not hit DoH")

                // 1c) WebRTC STUN Binding Request IP-leak hardening returns ICMPv4 unreachable
                val stunPayload = IpPackets.buildStunIpDiscovery(0x2112A442, "", 0)
                val stunPkt = IpPackets.buildIpv4Udp(clientIp, loopbackIp, 53500, 3478, stunPayload)
                appToBridgeOut.write(stunPkt)
                appToBridgeOut.flush()

                val stunIcmp = readNextIpPacket(bridgeToAppIn)
                eq(stunIcmp[9].toInt() and 0xFF, IpPackets.PROTO_ICMP, "STUN leak blocked via ICMPv4")
                eq(stunIcmp[20].toInt() and 0xFF, 3, "ICMPv4 Type 3")
                eq(bridge.leaksBlocked.get(), 1, "leaksBlocked counter")

                // 2) Universal real-time UDP NAT relay over VpnService.protect()ed DatagramSocket
                DatagramSocket(0, InetAddress.getLoopbackAddress()).use { udpSrv ->
                    udpSrv.soTimeout = 3000
                    val srvThread = Thread {
                        val buf = ByteArray(512)
                        val dp = DatagramPacket(buf, buf.size)
                        udpSrv.receive(dp)
                        val msg = String(dp.data, 0, dp.length)
                        val reply = "UDP_PONG:$msg".toByteArray()
                        udpSrv.send(DatagramPacket(reply, reply.size, dp.socketAddress))
                    }.apply { isDaemon = true; start() }

                    val udpPayload = "FREEDOM_REALTIME_UDP_FRAME".toByteArray()
                    val udpOutPkt = IpPackets.buildIpv4Udp(clientIp, loopbackIp, 54000, udpSrv.localPort, udpPayload)
                    appToBridgeOut.write(udpOutPkt)
                    appToBridgeOut.flush()

                    val udpInPkt = readNextIpPacket(bridgeToAppIn)
                    val udpIn = IpPackets.parseUdp(udpInPkt)!!
                    eq(udpIn.srcPort, udpSrv.localPort, "UDP NAT reply srcPort")
                    eq(udpIn.dstPort, 54000, "UDP NAT reply dstPort")
                    eq(String(udpIn.payload), "UDP_PONG:FREEDOM_REALTIME_UDP_FRAME", "UDP NAT payload")
                    expect(protectedUdpCount.get() >= 1) { "protectDatagram must be called" }
                    srvThread.join(2000)
                }

                // 3) Universal TCP + Active Desync split over VpnService.protect()ed Socket
                ServerSocket(0, 8, InetAddress.getLoopbackAddress()).use { tcpSrv ->
                    tcpSrv.soTimeout = 3000
                    val httpReq = "GET / HTTP/1.1\r\nHost: cloudflare.com\r\n\r\n".toByteArray()
                    val srvThread = Thread {
                        tcpSrv.accept().use { conn ->
                            conn.soTimeout = 3000
                            val received = java.io.ByteArrayOutputStream()
                            val buf = ByteArray(256)
                            while (received.size() < httpReq.size) {
                                val n = conn.inputStream.read(buf)
                                if (n <= 0) break
                                received.write(buf, 0, n)
                            }
                            conn.outputStream.write("HTTP/1.1 200 FREEDOM_OK\r\n\r\n".toByteArray())
                            conn.outputStream.flush()
                        }
                    }.apply { isDaemon = true; start() }

                    // Send TCP SYN
                    val synPkt = IpPackets.buildIpv4Tcp(
                        srcIp = clientIp,
                        dstIp = loopbackIp,
                        srcPort = 55000,
                        dstPort = tcpSrv.localPort,
                        seq = 1000L,
                        ack = 0L,
                        flags = IpPackets.TCP_SYN,
                    )
                    appToBridgeOut.write(synPkt)
                    appToBridgeOut.flush()

                    val synAckPkt = readNextIpPacket(bridgeToAppIn)
                    val synAck = IpPackets.parseTcp(synAckPkt)!!
                    eq(synAck.flags and (IpPackets.TCP_SYN or IpPackets.TCP_ACK), IpPackets.TCP_SYN or IpPackets.TCP_ACK, "SYN+ACK flags")
                    eq(synAck.ack, 1001L, "SYN+ACK ack")

                    // Send PSH+ACK carrying HTTP request
                    val dataPkt = IpPackets.buildIpv4Tcp(
                        srcIp = clientIp,
                        dstIp = loopbackIp,
                        srcPort = 55000,
                        dstPort = tcpSrv.localPort,
                        seq = 1001L,
                        ack = (synAck.seq + 1L) and 0xFFFFFFFFL,
                        flags = IpPackets.TCP_PSH or IpPackets.TCP_ACK,
                        payload = httpReq,
                    )
                    appToBridgeOut.write(dataPkt)
                    appToBridgeOut.flush()

                    var gotResponse = ""
                    for (attempt in 0 until 4) {
                        val pkt = readNextIpPacket(bridgeToAppIn)
                        val seg = IpPackets.parseTcp(pkt)!!
                        if (seg.payload.isNotEmpty()) {
                            gotResponse += String(seg.payload)
                            break
                        }
                    }
                    eq(gotResponse, "HTTP/1.1 200 FREEDOM_OK\r\n\r\n", "TCP response payload")
                    expect(protectedTcpCount.get() >= 1) { "protectSocket must be called" }
                    expect(bridge.desyncedFlows.get() >= 1) { "desyncedFlows must be >= 1" }
                    srvThread.join(2000)
                }

                // 4) Wi-Fi <-> Mobile Data roaming rebind refreshes active UDP/TCP sockets without dropping TUN
                bridge.rebindActiveSessions()
                expect(bridge.roamingRebinds.get() >= 1) { "roamingRebinds must be >= 1" }
            }
        }
    }

    // ------------------------------------------------------------------ 24. Restricted ISP network simulation: TLS record fragmentation, STUN 74B, realtime UDP 0x05
    test("restricted network simulation: TLS record fragmentation, STUN 74B, and realtime UDP 0x05") {
        DiagnosticSession().use { s ->
            val srcIp = IpPackets.parseIpLiteral("10.215.173.1")!!
            val dstIp = IpPackets.parseIpLiteral("104.16.132.229")!!

            // 1) STUN 74-byte IP Discovery UDP datagram (`0x00 0x01 0x00 0x46`)
            val stunPayload = IpPackets.buildStunIpDiscovery(0x11223344, "10.215.173.1", 50001)
            eq(stunPayload.size, 74, "STUN IP discovery size")
            val stunPkt = IpPackets.buildIpv4Udp(srcIp, dstIp, 50001, 50000, stunPayload)
            val stunRes = s.desyncPacket(stunPkt, DesyncConfig(mode = DesyncMode.REALITY_VISION, fakeTtl = 3))
            eq(stunRes.status, Codes.OK, "STUN UDP desync status")
            eq(stunRes.protocol, 4, "PROTO_UDP_STUN_MEDIA (4)")
            eq(stunRes.packets.size, 2, "low-TTL decoy + real STUN UDP packet")

            // 2) Real-time UDP handshake (`0x05` + 16-byte offline magic)
            val realtimePayload = IpPackets.buildRealtimeUdpHandshake(48)
            val realtimePkt = IpPackets.buildIpv4Udp(srcIp, dstIp, 55123, 59100, realtimePayload)
            val realtimeRes = s.desyncPacket(realtimePkt, DesyncConfig(mode = DesyncMode.REALITY_VISION, fakeTtl = 3))
            eq(realtimeRes.status, Codes.OK, "Realtime UDP desync status")
            eq(realtimeRes.protocol, 5, "PROTO_UDP_REALTIME (5)")
            eq(realtimeRes.packets.size, 2, "low-TTL decoy + real Realtime UDP packet")

            // 3) TLS 1.3 ClientHello Record-Layer Multi-Fragmentation (RFC 8446 §5.1)
            val hostBytes = "example.org".toByteArray(Charsets.US_ASCII)
            val sniExtLen = 5 + hostBytes.size
            val extsLen = 4 + sniExtLen
            val bodyLen = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extsLen
            val recLen = 4 + bodyLen
            val ch = java.nio.ByteBuffer.allocate(5 + recLen).apply {
                put(0x16.toByte()); put(0x03.toByte()); put(0x01.toByte())
                putShort(recLen.toShort())
                put(0x01.toByte())
                put(0x00.toByte()); putShort(bodyLen.toShort())
                put(0x03.toByte()); put(0x03.toByte())
                put(ByteArray(32))
                put(0x00.toByte())
                putShort(2); put(0x13.toByte()); put(0x01.toByte())
                put(0x01.toByte()); put(0x00.toByte())
                putShort(extsLen.toShort())
                putShort(0x0000); putShort(sniExtLen.toShort())
                putShort((3 + hostBytes.size).toShort())
                put(0x00.toByte()); putShort(hostBytes.size.toShort())
                put(hostBytes)
            }.array()
            val tcpPkt = IpPackets.buildIpv4Tcp(srcIp, dstIp, 52000, 443, 1000L, 0L, IpPackets.TCP_PSH or IpPackets.TCP_ACK, payload = ch)
            val desyncRes = s.desyncPacket(tcpPkt, DesyncConfig(mode = DesyncMode.REALITY_VISION, fakeTtl = 4))
            val tcpChunks = IpPackets.extractOrderedStreamChunks(tcpPkt, ch, desyncRes)
            val tlsRecords = IpPackets.fragmentTlsClientHelloRecords(ch, tcpChunks)
            expect(tlsRecords.size >= 2) { "must fragment into multiple TLS 0x16 records" }
            for (rec in tlsRecords) {
                eq(rec[0].toInt() and 0xFF, 0x16, "each fragment is a valid TLS 0x16 record")
                expect(!String(rec, Charsets.ISO_8859_1).contains("example.org")) {
                    "no single TLS record may contain full SNI"
                }
            }
        }
    }

    // ------------------------------------------------------------------ 25. DNS Poisoning Detection, ICMP synthesis & Stream First-Flight Evasion
    test("DNS poison detection, ICMP unreachable synthesis, and stream planFirstPayload") {
        val q = Doh.query("example.org")!!

        // 1) ISP Poison detection: 195.175.254.2 / loopback / clean IP
        val poisonedIsp = dnsAnswer(q, byteArrayOf(195.toByte(), 175.toByte(), 254.toByte(), 2))
        expect(IpPackets.containsPoisonedDns(poisonedIsp)) { "must detect 195.175.254.2 as poisoned" }

        val poisonedLoopback = dnsAnswer(q, byteArrayOf(127, 0, 0, 1))
        expect(IpPackets.containsPoisonedDns(poisonedLoopback)) { "must detect 127.0.0.1 as poisoned" }

        val cleanAnswer = dnsAnswer(q, byteArrayOf(104.toByte(), 16.toByte(), 132.toByte(), 229.toByte()))
        expect(!IpPackets.containsPoisonedDns(cleanAnswer)) { "clean IP must not be flagged" }

        val minTtl = IpPackets.dnsMinTtl(cleanAnswer)
        eq(minTtl, 300L, "parsed DNS answer min TTL")

        // 2) ICMPv6 unreachable synthesis (RFC 4443 Type 1 Code 3) for immediate IPv4 fallback
        val mockIpv6 = ByteArray(40).apply {
            this[0] = 0x60 // IPv6 version 6
            this[6] = 6 // TCP
            this[7] = 64 // Hop limit
            // src: 2001:db8::1, dst: 2001:db8::2
            this[8] = 0x20; this[9] = 0x01; this[10] = 0x0d; this[11] = 0xb8.toByte(); this[23] = 1
            this[24] = 0x20; this[25] = 0x01; this[26] = 0x0d; this[27] = 0xb8.toByte(); this[39] = 2
        }
        val icmpv6 = IpPackets.buildIcmpv6Unreachable(mockIpv6)
        expect(icmpv6 != null) { "ICMPv6 packet must be synthesized" }
        eq(((icmpv6!![0].toInt() ushr 4) and 0x0F), 6, "ICMPv6 version")
        eq(icmpv6[6].toInt() and 0xFF, 58, "IPv6 Next Header = ICMPv6 (58)")
        eq(icmpv6[40].toInt() and 0xFF, 1, "ICMPv6 Type 1 (Destination Unreachable)")
        eq(icmpv6[41].toInt() and 0xFF, 3, "ICMPv6 Code 3 (Address Unreachable)")

        // 3) ICMPv4 unreachable synthesis for QUIC -> TCP fallback
        val clientIp = IpPackets.parseIpLiteral("10.215.173.1")!!
        val quicIp = IpPackets.parseIpLiteral("104.16.132.229")!!
        val quicPkt = IpPackets.buildIpv4Udp(clientIp, quicIp, 50000, 443, byteArrayOf(1, 2, 3, 4))
        val icmpv4 = IpPackets.buildIcmpv4Unreachable(quicPkt)
        expect(icmpv4 != null) { "ICMPv4 packet must be synthesized" }
        eq(icmpv4!![9].toInt() and 0xFF, 1, "IPv4 Proto = ICMP (1)")
        eq(icmpv4[20].toInt() and 0xFF, 3, "ICMPv4 Type 3 (Destination Unreachable)")
        eq(icmpv4[21].toInt() and 0xFF, 3, "ICMPv4 Code 3 (Port Unreachable)")

        // 4) SNI locator and planFirstPayload
        val hostBytes = "wikipedia.org".toByteArray(Charsets.US_ASCII)
        val sniExtLen = 5 + hostBytes.size
        val extsLen = 4 + sniExtLen
        val bodyLen = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extsLen
        val recLen = 4 + bodyLen
        val ch = java.nio.ByteBuffer.allocate(5 + recLen).apply {
            put(0x16.toByte()); put(0x03.toByte()); put(0x01.toByte())
            putShort(recLen.toShort())
            put(0x01.toByte())
            put(0x00.toByte()); putShort(bodyLen.toShort())
            put(0x03.toByte()); put(0x03.toByte())
            put(ByteArray(32))
            put(0x00.toByte())
            putShort(2); put(0x13.toByte()); put(0x01.toByte())
            put(0x01.toByte()); put(0x00.toByte())
            putShort(extsLen.toShort())
            putShort(0x0000); putShort(sniExtLen.toShort())
            putShort((3 + hostBytes.size).toShort())
            put(0x00.toByte()); putShort(hostBytes.size.toShort())
            put(hostBytes)
        }.array()

        val sniPos = IpPackets.findClientHelloSni(ch)
        expect(sniPos != null) { "must locate SNI offset in ClientHello" }
        eq(String(ch, sniPos!!.first, sniPos.second, Charsets.US_ASCII), "wikipedia.org", "extracted SNI string")

        val planned = IpPackets.planFirstPayload(ch, listOf(ch))
        expect(planned.size >= 2) { "planFirstPayload must fragment ClientHello" }
        for (f in planned) {
            eq(f[0].toInt() and 0xFF, 0x16, "each planned fragment is a valid TLS 0x16 record")
            expect(!String(f, Charsets.ISO_8859_1).contains("wikipedia.org")) {
                "no single planned fragment contains full wikipedia.org SNI"
            }
        }
    }

    // ------------------------------------------------------------------ 26. ExitRelayConfig & IP-leak hardening helpers
    test("ExitRelayConfig parsing, leak-risk ports, and plaintext HTTP IP header stripping") {
        val tor = ExitRelayConfig.parse("tor")!!
        eq(tor.scheme, "socks5", "tor scheme")
        eq(tor.host, "127.0.0.1", "tor host")
        eq(tor.port, 9050, "tor port")
        expect(tor.isLoopback()) { "tor must be loopback" }

        val customSocks = ExitRelayConfig.parse("socks5://alice:s3cr3t@198.51.100.10:1080")!!
        eq(customSocks.scheme, "socks5", "custom scheme")
        eq(customSocks.host, "198.51.100.10", "custom host")
        eq(customSocks.port, 1080, "custom port")
        eq(customSocks.username, "alice", "username")
        eq(customSocks.password, "s3cr3t", "password")
        expect(!customSocks.isLoopback()) { "public relay not loopback" }

        val httpsRelay = ExitRelayConfig.parse("https://proxy.example.org")!!
        eq(httpsRelay.scheme, "https", "https scheme")
        eq(httpsRelay.port, 443, "default https port")

        eq(ExitRelayConfig.parse(""), null, "blank relay")
        eq(ExitRelayConfig.parse("ftp://bad.example.org:21"), null, "unsupported scheme")

        expect(IpPackets.isLeakRiskUdpPort(3478) && IpPackets.isLeakRiskUdpPort(19302) && IpPackets.isLeakRiskUdpPort(5353)) { "leak UDP ports" }
        expect(!IpPackets.isLeakRiskUdpPort(443)) { "443 not leak-risk UDP port" }
        expect(IpPackets.isLeakRiskTcpPort(3478) && IpPackets.isLeakRiskTcpPort(5349)) { "leak TCP ports" }

        val rawHttp = ("GET /ip HTTP/1.1\r\nHost: api.ipify.org\r\n" +
            "X-Forwarded-For: 176.89.26.149\r\nX-Real-IP: 10.0.0.2\r\nForwarded: for=1.2.3.4\r\nVia: 1.1 carrier\r\n\r\nbody").toByteArray()
        val stripped = String(IpPackets.stripPlainHttpClientIpHeaders(rawHttp), Charsets.ISO_8859_1)
        expect("Host: api.ipify.org" in stripped && stripped.endsWith("\r\n\r\nbody")) { "keeps safe HTTP header and body: $stripped" }
        expect("176.89.26.149" !in stripped && "X-Real-IP" !in stripped && "Forwarded" !in stripped && "Via:" !in stripped) { "strips leaking headers: $stripped" }

        val tls = byteArrayOf(0x16, 0x03, 0x01, 0x00, 0x20) + ByteArray(32)
        expect(IpPackets.stripPlainHttpClientIpHeaders(tls) === tls) { "binary TLS payload untouched" }
    }

    // ------------------------------------------------------------------ 27. TunBridge through loopback Exit Relay & strict leak guard
    test("TunBridge routes TCP through HTTP CONNECT Exit Relay, strips leak headers, and blocks TCP-53 under Kill Switch") {
        DiagnosticSession(fastConfig).use { s ->
            val appToBridgeIn = java.io.PipedInputStream(65536)
            val appToBridgeOut = java.io.PipedOutputStream(appToBridgeIn)
            val bridgeToAppIn = java.io.PipedInputStream(65536)
            val bridgeToAppOut = java.io.PipedOutputStream(bridgeToAppIn)

            fun readNextIp(input: java.io.InputStream): ByteArray {
                val hdr = ByteArray(20)
                var read = 0
                while (read < 20) {
                    val n = input.read(hdr, read, 20 - read)
                    if (n < 0) error("EOF")
                    read += n
                }
                val totalLen = IpPackets.u16(hdr, 2)
                val full = ByteArray(totalLen)
                System.arraycopy(hdr, 0, full, 0, 20)
                while (read < totalLen) {
                    val n = input.read(full, read, totalLen - read)
                    if (n < 0) error("EOF")
                    read += n
                }
                return full
            }

            ServerSocket(0, 8, InetAddress.getLoopbackAddress()).use { originSrv ->
                originSrv.soTimeout = 4000
                val receivedOnOrigin = AtomicReference("")
                val originThread = Thread {
                    originSrv.accept().use { conn ->
                        conn.soTimeout = 3000
                        val sb = StringBuilder()
                        while (true) {
                            val b = conn.inputStream.read()
                            if (b < 0) break
                            sb.append(b.toChar())
                            if (sb.endsWith("\r\n\r\n")) break
                        }
                        receivedOnOrigin.set(sb.toString())
                        conn.outputStream.write("HTTP/1.1 200 MASKED_OK\r\n\r\n".toByteArray())
                        conn.outputStream.flush()
                    }
                }.apply { isDaemon = true; start() }

                ServerSocket(0, 8, InetAddress.getLoopbackAddress()).use { relaySrv ->
                    relaySrv.soTimeout = 4000
                    val connectTarget = AtomicReference("")
                    val relayThread = Thread {
                        relaySrv.accept().use { client ->
                            client.soTimeout = 3000
                            val rIn = client.inputStream
                            val rOut = client.outputStream
                            val sb = StringBuilder()
                            while (true) {
                                val b = rIn.read()
                                if (b < 0) break
                                sb.append(b.toChar())
                                if (sb.endsWith("\r\n\r\n")) break
                            }
                            val reqLine = sb.toString().lineSequence().firstOrNull().orEmpty()
                            connectTarget.set(reqLine.substringAfter("CONNECT ").substringBefore(' '))
                            Socket(InetAddress.getLoopbackAddress(), originSrv.localPort).use { upstream ->
                                rOut.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray())
                                rOut.flush()
                                val fwd = Thread {
                                    runCatching { rIn.transferTo(upstream.outputStream); upstream.shutdownOutput() }
                                }.apply { isDaemon = true; start() }
                                runCatching { upstream.inputStream.transferTo(rOut); rOut.flush() }
                                fwd.join(2000)
                            }
                        }
                    }.apply { isDaemon = true; start() }

                    val clientIp = IpPackets.parseIpLiteral(TunBridge.VPN_CLIENT_IP)!!
                    val loopbackIp = IpPackets.parseIpLiteral("127.0.0.1")!!
                    val fakePeerIp = IpPackets.parseIpLiteral("198.51.100.77")!!

                    TunBridge(
                        session = s,
                        tunInput = appToBridgeIn,
                        tunOutput = bridgeToAppOut,
                        strictKillSwitch = true,
                        hardenStunLeaks = true,
                        exitRelayUri = "http://127.0.0.1:${relaySrv.localPort}",
                    ).use { bridge ->
                        bridge.start()
                        expect(bridge.isExitRelayActive) { "exit relay must be active" }

                        // 1) TCP SYN to port 53 must immediately RST under Strict Kill Switch
                        val tcpDnsSyn = IpPackets.buildIpv4Tcp(clientIp, loopbackIp, 56001, 53, 100L, 0L, IpPackets.TCP_SYN)
                        appToBridgeOut.write(tcpDnsSyn)
                        appToBridgeOut.flush()
                        val dnsRst = IpPackets.parseTcp(readNextIp(bridgeToAppIn))!!
                        expect((dnsRst.flags and IpPackets.TCP_RST) != 0) { "TCP:53 must be reset under Kill Switch" }

                        // 2) TCP connection routed through Exit Relay (CONNECT) with X-Forwarded-For stripped
                        val syn = IpPackets.buildIpv4Tcp(clientIp, fakePeerIp, 56002, originSrv.localPort, 2000L, 0L, IpPackets.TCP_SYN)
                        appToBridgeOut.write(syn)
                        appToBridgeOut.flush()
                        val synAck = IpPackets.parseTcp(readNextIp(bridgeToAppIn))!!
                        eq(synAck.flags and (IpPackets.TCP_SYN or IpPackets.TCP_ACK), IpPackets.TCP_SYN or IpPackets.TCP_ACK, "SYN+ACK")

                        val dirtyHttp = "GET /ip HTTP/1.1\r\nHost: test.local\r\nX-Forwarded-For: 176.89.26.149\r\n\r\n".toByteArray()
                        val data = IpPackets.buildIpv4Tcp(
                            clientIp, fakePeerIp, 56002, originSrv.localPort,
                            2001L, (synAck.seq + 1L) and 0xFFFFFFFFL,
                            IpPackets.TCP_PSH or IpPackets.TCP_ACK, payload = dirtyHttp,
                        )
                        appToBridgeOut.write(data)
                        appToBridgeOut.flush()

                        var resp = ""
                        for (attempt in 0 until 4) {
                            val seg = IpPackets.parseTcp(readNextIp(bridgeToAppIn))!!
                            if (seg.payload.isNotEmpty()) {
                                resp = String(seg.payload)
                                break
                            }
                        }
                        eq(resp, "HTTP/1.1 200 MASKED_OK\r\n\r\n", "relayed TCP response")
                        eq(connectTarget.get(), "198.51.100.77:${originSrv.localPort}", "CONNECT target")
                        expect("176.89.26.149" !in receivedOnOrigin.get()) { "X-Forwarded-For must be stripped before Exit Relay" }
                        expect(bridge.leaksBlocked.get() >= 2) { "expected >=2 blocked leaks (TCP:53 + X-Forwarded-For)" }
                        relayThread.join(2500)
                        originThread.join(2500)
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------ 28. Native WireGuard RFC 7748 + JNI handshake lifecycle
    test("28. Native WireGuard RFC 7748 public key and JNI handle lifecycle") {
        // RFC 7748 Section 6.1 test vector for Curve25519 scalar multiplication
        val rfcPrivHex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        val rfcPubHex = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        val priv = rfcPrivHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val expectedPub = rfcPubHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val computedPub = Native.wgPublicKey(priv)
        expect(computedPub != null && computedPub.contentEquals(expectedPub)) { "wgPublicKey must match RFC 7748 basepoint vector" }

        val peerPriv = ByteArray(32) { i -> (0x41 + i).toByte() }
        val peerPub = Native.wgPublicKey(peerPriv)!!
        val h = Native.wgCreate(priv, peerPub)
        expect(h != 0L) { "wgCreate must return a non-zero handle" }
        try {
            val ephPriv = ByteArray(32) { i -> (0x11 + i).toByte() }
            val tai64n = ByteArray(12) { i -> (i + 1).toByte() }
            val initPkt = Native.wgHandshakeInit(h, ephPriv, tai64n)
            expect(initPkt != null && initPkt.size == 148 && initPkt[0].toInt() == 1) {
                "WireGuard Handshake Initiation must be 148 bytes starting with type 1"
            }
        } finally {
            eq(Native.wgDestroy(h), Codes.OK, "wgDestroy")
        }
    }

    // ------------------------------------------------------------------ 29. IpPackets.rewriteIpv4Nat & TCP SYN MSS clamping
    test("29. IpPackets.rewriteIpv4Nat updates src/dst, clamps MSS to 1240, and preserves valid checksums") {
        val oldSrc = IpPackets.parseIpLiteral("10.89.0.2")!!
        val newSrc = IpPackets.parseIpLiteral("172.16.0.2")!!
        val dst = IpPackets.parseIpLiteral("93.184.216.34")!!
        val syn = IpPackets.buildIpv4Tcp(oldSrc, dst, 44321, 443, 1000L, 0L, IpPackets.TCP_SYN, mssOption = 1460)
        val natted = IpPackets.rewriteIpv4Nat(syn, newSrcIp = newSrc, clampMss = 1240)!!

        val ipHdr = IpPackets.parseIpv4(natted)!!
        eq(ipHdr.srcIp, newSrc, "NAT must rewrite source IPv4")
        eq(ipHdr.dstIp, dst, "NAT preserves destination IPv4")
        eq(IpPackets.ipv4Checksum(natted, 0, ipHdr.ihl), 0, "IPv4 checksum must validate to 0")
        eq(IpPackets.transportChecksumV4(ipHdr.srcIp, ipHdr.dstIp, IpPackets.PROTO_TCP, natted, ipHdr.ihl, ipHdr.totalLen - ipHdr.ihl), 0, "TCP checksum must validate to 0")

        // Verify MSS option bytes (kind=2, len=4, val=1240)
        val clampedMss = IpPackets.u16(natted, ipHdr.ihl + 22)
        eq(clampedMss, 1240, "SYN MSS option must be clamped to 1240")
    }

    // ------------------------------------------------------------------ 30. DevicePersona HTTP spoofing & geo-header stripping
    test("30. IpPackets.sanitizePlainHttpHeaders injects futuristic DevicePersona and strips leak headers") {
        val raw = (
            "GET /who HTTP/1.1\r\n" +
                "Host: check.local\r\n" +
                "User-Agent: Dalvik/2.1.0 (Linux; Android 17; SM-S911B)\r\n" +
                "Sec-CH-UA-Model: \"SM-S911B\"\r\n" +
                "X-Forwarded-For: 192.0.2.55\r\n" +
                "X-Geo-Location: 41.01,28.97\r\n" +
                "Accept-Language: tr-TR,tr;q=0.9\r\n\r\n"
            ).toByteArray(Charsets.ISO_8859_1)

        val spoofed = String(IpPackets.sanitizePlainHttpHeaders(raw, DevicePersona.IPHONE_19_BETA, stripGeoHeaders = true), Charsets.ISO_8859_1)
        expect("SM-S911B" !in spoofed) { "Real device model must be stripped" }
        expect("192.0.2.55" !in spoofed) { "X-Forwarded-For must be stripped" }
        expect("41.01,28.97" !in spoofed) { "X-Geo-Location must be stripped" }
        expect("iPhone19,3" in spoofed && "iPhone OS 21_0" in spoofed) { "Futuristic iPhone 19 Beta UA must be injected" }
        expect("en-US" in spoofed && "tr-TR" !in spoofed) { "Accept-Language should normalize to en-US under persona" }

        val untouched = IpPackets.sanitizePlainHttpHeaders(raw, DevicePersona.OFF, stripGeoHeaders = false)
        expect("SM-S911B" in String(untouched, Charsets.ISO_8859_1)) { "DevicePersona.OFF must preserve User-Agent" }
    }

    // ------------------------------------------------------------------ 31. DNS AAAA query detection, NODATA synthesis & DNS rebinding protection
    test("31. DNS QTYPE parsing, AAAA NODATA synthesis, and DNS-rebinding private-range detection") {
        val aaaaQuery = Doh.query("example.com", qtype = 28)!!
        eq(IpPackets.parseDnsQuestionType(aaaaQuery), 28, "parseDnsQuestionType must return 28 for AAAA")
        val nodata = IpPackets.buildDnsNodataAaaa(aaaaQuery)
        expect((nodata[3].toInt() and 0x0F) == 0 && IpPackets.u16(nodata, 6) == 0) {
            "buildDnsNodataAaaa must set RCODE=0 (NOERROR) and ANCOUNT=0"
        }

        fun fakeDnsReply(aBytes: ByteArray): ByteArray {
            val qFull = Doh.query("rebind.test")!!
            val qLen = if (IpPackets.u16(qFull, 10) > 0) qFull.size - 11 else qFull.size
            val out = ByteArray(qLen + 16)
            System.arraycopy(qFull, 0, out, 0, qLen)
            out[2] = 0x81.toByte(); out[3] = 0x80.toByte()
            out[7] = 1 // ANCOUNT = 1
            out[10] = 0; out[11] = 0 // ARCOUNT = 0
            var p = qLen
            out[p++] = 0xC0.toByte(); out[p++] = 12 // ptr to QNAME
            out[p++] = 0; out[p++] = 1 // TYPE A
            out[p++] = 0; out[p++] = 1 // CLASS IN
            out[p++] = 0; out[p++] = 0; out[p++] = 0; out[p++] = 60 // TTL 60
            out[p++] = 0; out[p++] = 4 // RDLENGTH 4
            System.arraycopy(aBytes, 0, out, p, 4)
            return out
        }

        expect(IpPackets.containsPoisonedDns(fakeDnsReply(byteArrayOf(192.toByte(), 168.toByte(), 1, 1)))) { "192.168.1.1 rebinding must be caught" }
        expect(IpPackets.containsPoisonedDns(fakeDnsReply(byteArrayOf(10, 0, 0, 1)))) { "10.0.0.1 rebinding must be caught" }
        expect(IpPackets.containsPoisonedDns(fakeDnsReply(byteArrayOf(169.toByte(), 254.toByte(), 169.toByte(), 254.toByte())))) { "169.254.169.254 metadata SSRF must be caught" }
        expect(!IpPackets.containsPoisonedDns(fakeDnsReply(byteArrayOf(1, 1, 1, 1)))) { "1.1.1.1 public IP must be allowed" }
    }

    // ------------------------------------------------------------------ 32. Expanded OEM/Geo/Fingerprint tracker sinkhole
    test("32. Expanded telemetry, location-beacon & fingerprinting domains blocked") {
        expect(IpPackets.isTrackerOrAdDomain("location.services.mozilla.com")) { "Mozilla geo beacon must be blocked" }
        expect(IpPackets.isTrackerOrAdDomain("diagmon.samsung.com")) { "OEM telemetry must be blocked" }
        expect(IpPackets.isTrackerOrAdDomain("cdn.fpjs.io")) { "FingerprintJS must be blocked" }
        expect(!IpPackets.isTrackerOrAdDomain("api.github.com")) { "Clean API domain must not be blocked" }
    }

    // ------------------------------------------------------------------ 33. WarpIdentity serialization & WarpProvisioner JSON parser
    test("33. WarpIdentity round-trip serialization and WarpProvisioner registration JSON parser") {
        val priv = ByteArray(32) { i -> (i + 3).toByte() }
        val peerPub = ByteArray(32) { i -> (i + 9).toByte() }
        val privB64 = java.util.Base64.getEncoder().encodeToString(priv)
        val peerPubB64 = java.util.Base64.getEncoder().encodeToString(peerPub)

        val sampleJson = """
            {
              "id": "dev-1234",
              "token": "tok-secret-99",
              "warp_enabled": false,
              "config": {
                "peers": [
                  {
                    "public_key": "$peerPubB64",
                    "endpoint": { "v4": "162.159.192.1:2408", "v6": "[2606:4700:d0::a29f:c001]:2408" }
                  }
                ],
                "interface": {
                  "addresses": { "v4": "172.16.0.2/32", "v6": "2606:4700:110::/128" }
                }
              }
            }
        """.trimIndent()

        val parsed = WarpProvisioner.parseRegistrationJson(sampleJson, privB64)
        expect(parsed != null && parsed.isValid()) { "WARP registration JSON must parse into a valid WarpIdentity" }
        eq(parsed!!.clientIpv4, "172.16.0.2", "clientIpv4")
        eq(parsed.endpointHost, "162.159.192.1", "endpointHost")
        eq(parsed.endpointPort, 2408, "endpointPort")
        eq(parsed.deviceId, "dev-1234", "deviceId")

        val roundTrip = WarpIdentity.deserialize(parsed.serialize())
        eq(roundTrip?.privateKeyB64, parsed.privateKeyB64, "serialized privateKeyB64")
        eq(roundTrip?.peerPublicKeyB64, parsed.peerPublicKeyB64, "serialized peerPublicKeyB64")
        eq(roundTrip?.clientIpv4, parsed.clientIpv4, "serialized clientIpv4")
    }

    test("URL tracking param stripping and WarpIdentity reservedBytes") {
        val (cleanLine, changed) = IpPackets.stripUrlTrackingParamsFromRequestLine(
            "GET /watch?v=123&utm_source=x&fbclid=abc&si=99 HTTP/1.1"
        )
        expect(changed) { "expected tracking params stripped" }
        eq(cleanLine, "GET /watch?v=123 HTTP/1.1", "stripped request line")

        val req = "GET /page?gclid=1&keep=yes HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n"
            .toByteArray(Charsets.ISO_8859_1)
        val sanitized = String(IpPackets.sanitizePlainHttpHeaders(req, DevicePersona.ANDROID_19_QUANTUM), Charsets.ISO_8859_1)
        expect(sanitized.contains("GET /page?keep=yes HTTP/1.1")) { "sanitized url: $sanitized" }
        expect(!sanitized.contains("X-Forwarded-For")) { "stripped X-Forwarded-For" }

        val id = WarpIdentity(
            privateKeyB64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            peerPublicKeyB64 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
            clientIpv4 = "172.16.0.2",
            endpointHost = "162.159.192.1",
            clientIdB64 = "wP4B",
        )
        val res = id.reservedBytes()
        eq(res.size, 3, "reservedBytes length")
        eq(res[0].toInt() and 0xFF, 0xC0, "reserved[0]")
        eq(res[1].toInt() and 0xFF, 0xFE, "reserved[1]")
        eq(res[2].toInt() and 0xFF, 0x01, "reserved[2]")
    }

    test("35. Windows dark theme, FreedomButton, and vector panels never render white native chrome") {
        FreedomDarkTheme.install()
        val lafClass = javax.swing.UIManager.getLookAndFeel().javaClass.name
        expect("WindowsLookAndFeel" !in lafClass) { "Must not use WindowsLookAndFeel: $lafClass" }

        val btn = FreedomButton(
            "ÖZGÜR AĞ TEST",
            fillColor = java.awt.Color(15, 27, 46),
            textColor = java.awt.Color(226, 232, 240),
            borderColor = java.awt.Color(51, 65, 85),
        )
        expect(!btn.isContentAreaFilled && !btn.isBorderPainted && !btn.isOpaque) {
            "FreedomButton must disable default Swing content/border/opaque painting"
        }
        btn.setSize(180, 38)
        val img = java.awt.image.BufferedImage(180, 38, java.awt.image.BufferedImage.TYPE_INT_ARGB)
        val g2 = img.createGraphics()
        btn.paint(g2)
        g2.dispose()

        // Interior corner away from glyphs must show dark fill (15, 27, 46), never white/light native grey
        val sample = java.awt.Color(img.getRGB(8, 8), true)
        expect(sample.red < 60 && sample.green < 60 && sample.blue < 90) {
            "Button fill must stay dark, got rgb=(${sample.red},${sample.green},${sample.blue})"
        }

        // Verify dark checkbox icon paints non-white background
        val cbImg = java.awt.image.BufferedImage(20, 20, java.awt.image.BufferedImage.TYPE_INT_ARGB)
        val cbG = cbImg.createGraphics()
        DarkCheckBoxIcon(false).paintIcon(null, cbG, 2, 2)
        cbG.dispose()
        val cbPixel = java.awt.Color(cbImg.getRGB(10, 10), true)
        expect(cbPixel.red < 60 && cbPixel.green < 60 && cbPixel.blue < 90) {
            "DarkCheckBoxIcon interior must be dark, got $cbPixel"
        }

        // Verify hero & sparkline & stat card paint cleanly onto offscreen Graphics2D
        val hero = ModernPowerShieldPanel().apply { setSize(320, 180) }
        val spark = ThroughputSparklinePanel().apply { setSize(320, 80); updateMetrics(12.5f, 3.1f, 4096, 1024) }
        val stat = ModernStatCard(0, "TEST", java.awt.Color(16, 185, 129)).apply { setSize(160, 70) }
        try {
            val canvas = java.awt.image.BufferedImage(320, 180, java.awt.image.BufferedImage.TYPE_INT_ARGB)
            val cg = canvas.createGraphics()
            hero.paint(cg)
            spark.paint(cg)
            stat.paint(cg)
            cg.dispose()
        } finally {
            hero.stop()
        }
    }

    // ------------------------------------------------------------------ 36. UserspaceTcpStack RFC-793 loopback test
    test("36. UserspaceTcpStack RFC-793 handshake, MSS chunking, RTO retransmit, and OOO reassembly") {
        val clientIp = IpPackets.parseIpLiteral("172.16.0.2")!!
        val remoteIp = IpPackets.parseIpLiteral("93.184.216.34")!!
        val remotePort = 443
        val serverIss = 900000L
        var peerRcvNxt = 0L
        var droppedFirstData = false
        val peerReceived = java.io.ByteArrayOutputStream()
        val peerLock = Object()
        var clientLocalPort = 0
        lateinit var stack: UserspaceTcpStack

        val peerQueue = java.util.concurrent.LinkedBlockingQueue<ByteArray>()
        stack = UserspaceTcpStack(
            clientIpInt = clientIp,
            sendRawIp = { pkt ->
                peerQueue.offer(pkt)
                true
            },
            mtu = 1280,
        )

        val peerDone = AtomicBoolean(false)
        val responseChunksSent = AtomicBoolean(false)
        val expectedSendBytes = 16500
        val outPayload = ByteArray(expectedSendBytes) { idx -> ((idx * 31 + 7) and 0xFF).toByte() }
        val oooPart1 = "FIRST-CHUNK-HEADER-".toByteArray(Charsets.US_ASCII)
        val oooPart2 = "SECOND-CHUNK-TAIL!".toByteArray(Charsets.US_ASCII)

        val peerThread = Thread {
            while (!peerDone.get()) {
                val pkt = peerQueue.poll(30, java.util.concurrent.TimeUnit.MILLISECONDS) ?: continue
                val ip = IpPackets.parseIpv4(pkt) ?: continue
                val seg = IpPackets.parseTcp(pkt, ip) ?: continue
                clientLocalPort = seg.srcPort
                if ((seg.flags and IpPackets.TCP_SYN) != 0 && (seg.flags and IpPackets.TCP_ACK) == 0) {
                    peerRcvNxt = (seg.seq + 1L) and 0xFFFFFFFFL
                    val synAck = IpPackets.buildIpv4Tcp(
                        srcIp = remoteIp, dstIp = clientIp, srcPort = remotePort, dstPort = clientLocalPort,
                        seq = serverIss, ack = peerRcvNxt,
                        flags = IpPackets.TCP_SYN or IpPackets.TCP_ACK, window = 32768, mssOption = 1200,
                    )
                    stack.onInboundIpPacket(synAck)
                } else if (seg.payload.isNotEmpty()) {
                    // Deliberately drop the very first data segment once to verify RTO retransmission
                    if (!droppedFirstData) {
                        droppedFirstData = true
                        continue
                    }
                    expect(seg.payload.size <= 1220) { "MSS clamp violation: chunk size ${seg.payload.size}" }
                    if (seg.seq == peerRcvNxt) {
                        synchronized(peerLock) {
                            peerReceived.write(seg.payload)
                        }
                        peerRcvNxt = (peerRcvNxt + seg.payload.size) and 0xFFFFFFFFL
                    }
                    val ack = IpPackets.buildIpv4Tcp(
                        srcIp = remoteIp, dstIp = clientIp, srcPort = remotePort, dstPort = clientLocalPort,
                        seq = (serverIss + 1L) and 0xFFFFFFFFL, ack = peerRcvNxt,
                        flags = IpPackets.TCP_ACK, window = 32768,
                    )
                    stack.onInboundIpPacket(ack)

                    if (synchronized(peerLock) { peerReceived.size() } >= expectedSendBytes &&
                        responseChunksSent.compareAndSet(false, true)
                    ) {
                        val s1 = (serverIss + 1L) and 0xFFFFFFFFL
                        val s2 = (s1 + oooPart1.size) and 0xFFFFFFFFL
                        // Deliver chunk 2 BEFORE chunk 1 (out-of-order), then chunk 1, then FIN
                        stack.onInboundIpPacket(
                            IpPackets.buildIpv4Tcp(
                                srcIp = remoteIp, dstIp = clientIp, srcPort = remotePort, dstPort = clientLocalPort,
                                seq = s2, ack = peerRcvNxt, flags = IpPackets.TCP_PSH or IpPackets.TCP_ACK, payload = oooPart2,
                            ),
                        )
                        stack.onInboundIpPacket(
                            IpPackets.buildIpv4Tcp(
                                srcIp = remoteIp, dstIp = clientIp, srcPort = remotePort, dstPort = clientLocalPort,
                                seq = s1, ack = peerRcvNxt, flags = IpPackets.TCP_PSH or IpPackets.TCP_ACK, payload = oooPart1,
                            ),
                        )
                        stack.onInboundIpPacket(
                            IpPackets.buildIpv4Tcp(
                                srcIp = remoteIp, dstIp = clientIp, srcPort = remotePort, dstPort = clientLocalPort,
                                seq = (s2 + oooPart2.size) and 0xFFFFFFFFL, ack = peerRcvNxt, flags = IpPackets.TCP_FIN or IpPackets.TCP_ACK,
                            ),
                        )
                    }
                }
            }
        }.apply { isDaemon = true; start() }

        try {
            stack.use { st ->
                st.connect(remoteIp, remotePort, 4000).use { sock ->
                    sock.soTimeoutMs = 5000
                    sock.outputStream.write(outPayload)
                    sock.outputStream.flush()
                    val respBytes = sock.inputStream.readAllBytes()
                    eq(String(respBytes, Charsets.US_ASCII), "FIRST-CHUNK-HEADER-SECOND-CHUNK-TAIL!", "OOO reassembled response before FIN EOF")
                }
                val got = synchronized(peerLock) { peerReceived.toByteArray() }
                expect(got.contentEquals(outPayload)) { "All 16500 bytes must match cleanly (got=${got.size})" }
                expect(st.retransmits.get() >= 1L) { "Expected >=1 RTO retransmission after intentional packet drop" }
            }
        } finally {
            peerDone.set(true)
            peerThread.join(1500)
        }
    }

    // ------------------------------------------------------------------ 37. WindowsNextGenProxy HTTP CONNECT & 4-way TLS retry
    test("37. WindowsNextGenProxy HTTP CONNECT, SNI TLS record fragmentation, and adaptive 4-way RST retry") {
        val fakeDns = FakeDns()
        try {
            val attempts = AtomicInteger(0)
            val secondFlightBytes = AtomicReference(ByteArray(0))

            ServerSocket(0, 8, InetAddress.getLoopbackAddress()).use { origin ->
                origin.soTimeout = 6000
                val srvThread = Thread {
                    while (!origin.isClosed) {
                        val c = try { origin.accept() } catch (_: Throwable) { break }
                        c.soTimeout = 3000
                        val attemptIdx = attempts.incrementAndGet()
                        Thread {
                            c.use { sock ->
                                val buf = ByteArray(8192)
                                if (attemptIdx == 1) {
                                    // Read first chunk then abruptly kill connection to mimic ISP DPI RST on attempt 0
                                    runCatching { sock.inputStream.read(buf) }
                                    runCatching { sock.setSoLinger(true, 0) }
                                } else {
                                    val acc = java.io.ByteArrayOutputStream()
                                    sock.soTimeout = 120
                                    while (true) {
                                        val n = try { sock.inputStream.read(buf) } catch (_: SocketTimeoutException) { break } catch (_: Throwable) { break }
                                        if (n <= 0) break
                                        acc.write(buf, 0, n)
                                    }
                                    val bytes = acc.toByteArray()
                                    if (bytes.isNotEmpty() && secondFlightBytes.get().isEmpty()) {
                                        secondFlightBytes.set(bytes)
                                    }
                                    sock.outputStream.write("DPI_BYPASSED_TLS_OK".toByteArray(Charsets.US_ASCII))
                                    sock.outputStream.flush()
                                }
                            }
                        }.apply { isDaemon = true; start() }
                    }
                }.apply { isDaemon = true; start() }

                // Synthetic TLS 1.3 ClientHello carrying discord.com SNI
                val sniHost = "discord.com".toByteArray(Charsets.US_ASCII)
                val sniExtLen = 5 + sniHost.size
                val extsLen = 4 + sniExtLen
                val bodyLen = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extsLen
                val recLen = 4 + bodyLen
                val clientHello = java.nio.ByteBuffer.allocate(5 + recLen).apply {
                    put(0x16.toByte()); put(0x03.toByte()); put(0x01.toByte()); putShort(recLen.toShort())
                    put(0x01.toByte()); put(0x00.toByte()); putShort(bodyLen.toShort())
                    put(0x03.toByte()); put(0x03.toByte()); put(ByteArray(32))
                    put(0x00.toByte()); putShort(2); put(0x13.toByte()); put(0x01.toByte())
                    put(0x01.toByte()); put(0x00.toByte()); putShort(extsLen.toShort())
                    putShort(0x0000); putShort(sniExtLen.toShort())
                    putShort((3 + sniHost.size).toShort()); put(0x00.toByte()); putShort(sniHost.size.toShort()); put(sniHost)
                }.array()

                val dohStub = object : DohClient {
                    override fun post(url: String, body: ByteArray, timeoutMs: Int): DohResponse {
                        val q = Doh.query("discord.com", 1) ?: body
                        val out = java.io.ByteArrayOutputStream()
                        out.write(body, 0, 2)
                        out.write(byteArrayOf(0x81.toByte(), 0x80.toByte(), 0, 1, 0, 1, 0, 0, 0, 0))
                        var qEnd = 12
                        while (qEnd < q.size && q[qEnd].toInt() != 0) qEnd += (q[qEnd].toInt() and 0xFF) + 1
                        val qLen = (qEnd + 5).coerceAtMost(body.size)
                        out.write(body, 12, qLen - 12)
                        out.write(byteArrayOf(0xC0.toByte(), 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1))
                        return DohResponse(1, 500, EncProtocol.DOH, out.toByteArray())
                    }
                }

                WindowsNextGenProxy(
                    port = 0,
                    routeMode = WindowsRouteMode.HYBRID_DPI,
                    dohEndpoints = listOf("https://1.1.1.1/dns-query"),
                    dohClient = dohStub,
                    forceDirectForLoopback = true,
                    allowLoopbackDns = true,
                ).use { proxy ->
                    val proxyPort = proxy.start()
                    expect(proxyPort > 0) { "Proxy must bind loopback port" }

                    // Attempt #1: triggers DPI reset -> adaptive 4-way split retry -> succeeds cleanly
                    Socket(InetAddress.getLoopbackAddress(), proxyPort).use { c ->
                        c.soTimeout = 5000
                        val out = c.outputStream
                        out.write("CONNECT discord.com:${origin.localPort} HTTP/1.1\r\nHost: discord.com:${origin.localPort}\r\n\r\n".toByteArray(Charsets.US_ASCII))
                        out.flush()
                        val hdrBuf = StringBuilder()
                        while (true) {
                            val b = c.inputStream.read()
                            if (b < 0) break
                            hdrBuf.append(b.toChar())
                            if (hdrBuf.endsWith("\r\n\r\n")) break
                        }
                        expect("200" in hdrBuf.toString()) { "Expected HTTP 200 CONNECT banner, got: $hdrBuf" }
                        out.write(clientHello)
                        out.flush()
                        val reply = String(c.inputStream.readAllBytes(), Charsets.US_ASCII)
                        eq(reply, "DPI_BYPASSED_TLS_OK", "Adaptive 4-way split retry must succeed")
                    }

                    expect(attempts.get() >= 2) { "Expected DPI first-attempt fail then retry" }
                    expect(proxy.tlsAdaptiveRetries.get() >= 1L) { "Expected tlsAdaptiveRetries >= 1" }
                    expect(proxy.tlsSplit.get() >= 1L) { "Expected tlsSplit >= 1" }
                    val sent = secondFlightBytes.get()
                    var tlsRecCount = 0
                    var pos = 0
                    while (pos + 5 <= sent.size && (sent[pos].toInt() and 0xFF) == 0x16) {
                        val rlen = IpPackets.u16(sent, pos + 3)
                        tlsRecCount++
                        pos += 5 + rlen
                    }
                    expect(tlsRecCount >= 3) { "Expected multiple TLS 0x16 fragments on adaptive retry, got $tlsRecCount" }
                    expect(!String(sent, Charsets.ISO_8859_1).contains("discord.com")) { "Full SNI must never appear contiguous in a single TLS record" }

                    // Attempt #2: cached strategy connects in 1 origin attempt directly
                    val attemptsBefore = attempts.get()
                    Socket(InetAddress.getLoopbackAddress(), proxyPort).use { c2 ->
                        c2.soTimeout = 4000
                        c2.outputStream.write("CONNECT discord.com:${origin.localPort} HTTP/1.1\r\nHost: discord.com:${origin.localPort}\r\n\r\n".toByteArray(Charsets.US_ASCII))
                        c2.outputStream.flush()
                        val hb = StringBuilder()
                        while (!hb.endsWith("\r\n\r\n")) {
                            val b = c2.inputStream.read()
                            if (b < 0) break
                            hb.append(b.toChar())
                        }
                        c2.outputStream.write(clientHello)
                        c2.outputStream.flush()
                        val rep2 = String(c2.inputStream.readAllBytes(), Charsets.US_ASCII)
                        eq(rep2, "DPI_BYPASSED_TLS_OK", "Cached host strategy succeeds without retry")
                    }
                    eq(attempts.get(), attemptsBefore + 1, "Cached strategy should consume exactly 1 origin connection")
                }
                srvThread.join(1000)
            }
        } finally {
            fakeDns.close()
        }
    }

    // ------------------------------------------------------------------ 38. WindowsNextGenProxy SOCKS5, UDP block, tracker block & URL/Persona privacy
    test("38. WindowsNextGenProxy SOCKS5 CONNECT/UDP-block, tracker block, URL sanitization, and DevicePersona spoofing") {
        val originReceived = AtomicReference("")
        ServerSocket(0, 8, InetAddress.getLoopbackAddress()).use { origin ->
            origin.soTimeout = 5000
            val srv = Thread {
                while (!origin.isClosed) {
                    val c = try { origin.accept() } catch (_: Throwable) { break }
                    Thread {
                        c.use { s ->
                            s.soTimeout = 2000
                            val sb = StringBuilder()
                            while (!sb.endsWith("\r\n\r\n")) {
                                val ch = s.inputStream.read()
                                if (ch < 0) break
                                sb.append(ch.toChar())
                            }
                            if (sb.isNotEmpty()) {
                                originReceived.set(sb.toString())
                                s.outputStream.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK".toByteArray())
                                s.outputStream.flush()
                            } else {
                                s.outputStream.write("SOCKS_ECHO".toByteArray())
                                s.outputStream.flush()
                            }
                        }
                    }.apply { isDaemon = true; start() }
                }
            }.apply { isDaemon = true; start() }

            WindowsNextGenProxy(
                port = 0,
                routeMode = WindowsRouteMode.HYBRID_DPI,
                persona = DevicePersona.IPHONE_19_BETA,
                blockTrackers = true,
                stripUrlParams = true,
                blockQuicAndLeaks = true,
            ).use { proxy ->
                val pPort = proxy.start()

                // 1) SOCKS5 UDP ASSOCIATE (0x03) must be denied with status 0x02 (prevents WebRTC/QUIC UDP bypass)
                Socket(InetAddress.getLoopbackAddress(), pPort).use { s ->
                    s.soTimeout = 3000
                    s.outputStream.write(byteArrayOf(0x05, 0x01, 0x00)); s.outputStream.flush()
                    val m = s.inputStream.readNBytes(2)
                    eq(m[1].toInt(), 0, "SOCKS5 no-auth")
                    s.outputStream.write(byteArrayOf(0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0)); s.outputStream.flush()
                    val rep = s.inputStream.readNBytes(10)
                    eq(rep[1].toInt() and 0xFF, 0x02, "SOCKS5 UDP ASSOCIATE must return 0x02 denied")
                }

                // 2) Tracker domain blocked on HTTP CONNECT (403) and SOCKS5 CONNECT (0x02)
                Socket(InetAddress.getLoopbackAddress(), pPort).use { s ->
                    s.soTimeout = 3000
                    s.outputStream.write("CONNECT doubleclick.net:443 HTTP/1.1\r\nHost: doubleclick.net:443\r\n\r\n".toByteArray())
                    s.outputStream.flush()
                    val resp = String(s.inputStream.readAllBytes(), Charsets.US_ASCII)
                    expect("403 Forbidden" in resp) { "HTTP tracker CONNECT must return 403 Forbidden, got: $resp" }
                }
                Socket(InetAddress.getLoopbackAddress(), pPort).use { s ->
                    s.soTimeout = 3000
                    s.outputStream.write(byteArrayOf(0x05, 0x01, 0x00)); s.outputStream.flush()
                    s.inputStream.readNBytes(2)
                    val host = "doubleclick.net".toByteArray(Charsets.US_ASCII)
                    val req = byteArrayOf(0x05, 0x01, 0x00, 0x03, host.size.toByte()) + host + byteArrayOf(0x01, 0xBB.toByte())
                    s.outputStream.write(req); s.outputStream.flush()
                    val rep = s.inputStream.readNBytes(10)
                    eq(rep[1].toInt() and 0xFF, 0x02, "SOCKS5 tracker CONNECT must return 0x02 denied")
                }
                expect(proxy.trackersBlocked.get() >= 2L) { "Expected trackersBlocked >= 2" }

                // 3) SOCKS5 CONNECT 127.0.0.1:originPort succeeds cleanly
                Socket(InetAddress.getLoopbackAddress(), pPort).use { s ->
                    s.soTimeout = 3000
                    s.outputStream.write(byteArrayOf(0x05, 0x01, 0x00)); s.outputStream.flush()
                    s.inputStream.readNBytes(2)
                    val portHi = ((origin.localPort ushr 8) and 0xFF).toByte()
                    val portLo = (origin.localPort and 0xFF).toByte()
                    s.outputStream.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, portHi, portLo))
                    s.outputStream.flush()
                    val rep = s.inputStream.readNBytes(10)
                    eq(rep[1].toInt(), 0x00, "SOCKS5 CONNECT to origin must succeed")
                    s.outputStream.write("GET /socks HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".toByteArray())
                    s.outputStream.flush()
                    val body = String(s.inputStream.readAllBytes(), Charsets.US_ASCII)
                    expect(body.endsWith("OK")) { "Expected HTTP response via SOCKS5, got: $body" }
                }

                // 4) Plain HTTP URL tracking param stripping + DevicePersona User-Agent masking + X-Forwarded-For stripping
                Socket(InetAddress.getLoopbackAddress(), pPort).use { s ->
                    s.soTimeout = 3000
                    val dirtyReq = (
                        "GET http://127.0.0.1:${origin.localPort}/watch?utm_source=fb&fbclid=999&keep=1 HTTP/1.1\r\n" +
                            "Host: 127.0.0.1:${origin.localPort}\r\n" +
                            "User-Agent: Mozilla/5.0 (Windows NT 10.0) RealDesktop\r\n" +
                            "X-Forwarded-For: 176.89.26.149\r\n\r\n"
                        ).toByteArray(Charsets.US_ASCII)
                    s.outputStream.write(dirtyReq); s.outputStream.flush()
                    val resp = String(s.inputStream.readAllBytes(), Charsets.US_ASCII)
                    expect(resp.endsWith("OK")) { "Plain HTTP response must succeed: $resp" }
                }
                val forwarded = originReceived.get()
                expect("GET /watch?keep=1 HTTP/1.1" in forwarded) { "Tracking params must be stripped: $forwarded" }
                expect("iPhone19,3" in forwarded && "RealDesktop" !in forwarded) { "Persona User-Agent must replace real UA: $forwarded" }
                expect("176.89.26.149" !in forwarded) { "X-Forwarded-For must be stripped: $forwarded" }
                expect(proxy.paramsStripped.get() >= 1L) { "Expected paramsStripped >= 1" }
                expect(proxy.leaksBlocked.get() >= 1L) { "Expected leaksBlocked >= 1" }
            }
            srv.join(1000)
        }
    }

    // ------------------------------------------------------------------ 39. WindowsBrowserLauncher, runCli --help & MainWindow offscreen render
    test("39. WindowsBrowserLauncher hardened flags/prefs, runCli --help, and redesigned MainWindow offscreen render") {
        val tempDir = File(System.getProperty("java.io.tmpdir"), "freedom-browser-test-${System.nanoTime()}")
        try {
            val prefsFile = WindowsBrowserLauncher.prepareProfilePreferences(tempDir, blockLocation = true)
            val prefsJson = prefsFile.readText(Charsets.UTF_8)
            expect("\"disable_non_proxied_udp\"" in prefsJson) { "WebRTC policy missing from Preferences" }
            expect("\"nonproxied_udp_enabled\": false" in prefsJson) { "WebRTC nonproxied UDP toggle missing" }
            expect("\"geolocation\": 2" in prefsJson) { "Location blocking setting missing" }

            val args = WindowsBrowserLauncher.buildLaunchArgs(
                exePath = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                proxyPort = 18888,
                persona = DevicePersona.IPHONE_19_BETA,
                initialUrl = "https://discord.com/",
                profileRoot = tempDir,
            )
            expect("--disable-quic" in args) { "QUIC disable flag required to fix ERR_QUIC_PROTOCOL_ERROR" }
            expect("--proxy-server=http://127.0.0.1:18888" in args) { "Proxy server arg missing" }
            expect("--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1" in args) { "Host resolver rules missing" }
            expect("--force-webrtc-ip-handling-policy=disable_non_proxied_udp" in args) { "WebRTC CLI flag missing" }
            expect(args.any { it.startsWith("--user-agent=") && "iPhone19,3" in it }) { "Persona --user-agent flag missing" }
            expect(args.last() == "https://discord.com/") { "Initial URL must trail arguments" }
        } finally {
            tempDir.deleteRecursively()
        }

        eq(runCli(listOf("--help")), 0, "runCli --help must exit 0")

        FreedomDarkTheme.install()
        val win = MainWindow()
        try {
            val root = win.buildRootPanelForTest()
            root.setSize(1080, 760)
            root.doLayout()
            val canvas = java.awt.image.BufferedImage(1080, 760, java.awt.image.BufferedImage.TYPE_INT_ARGB)
            val g2 = canvas.createGraphics()
            root.paint(g2)
            g2.dispose()

            // Verify sidebar background & canvas edges remain dark obsidian (never light/white Win32 grey)
            val sidebarPx = java.awt.Color(canvas.getRGB(8, 380), true)
            val workspacePx = java.awt.Color(canvas.getRGB(1065, 745), true)
            expect(sidebarPx.red < 40 && sidebarPx.green < 40 && sidebarPx.blue < 60) {
                "Sidebar canvas must be dark obsidian, got $sidebarPx"
            }
            expect(workspacePx.red < 40 && workspacePx.green < 40 && workspacePx.blue < 60) {
                "Workspace background must be dark obsidian, got $workspacePx"
            }
        } finally {
            win.shutdown()
        }
    }

    // ------------------------------------------------------------------ 40. 34-icon SVG vector engine & SwingVectorIcons offscreen rendering
    test("40. Embedded 34-icon SVG path engine & SwingVectorIcons offscreen rasterization") {
        expect(FreedomIconId.entries.size >= 34) { "Expected at least 34 embedded icons, got ${FreedomIconId.entries.size}" }
        val expectedIds = listOf(
            FreedomIconId.SHIELD_CHECK, FreedomIconId.SHIELD_OFF, FreedomIconId.RADAR,
            FreedomIconId.SLIDERS, FreedomIconId.ACTIVITY, FreedomIconId.TERMINAL,
            FreedomIconId.GLOBE, FreedomIconId.ZAP, FreedomIconId.REFRESH_CW,
            FreedomIconId.ARROW_UP, FreedomIconId.ARROW_DOWN, FreedomIconId.CHEVRON_DOWN,
        )
        expectedIds.forEach { expect(it in FreedomIconId.entries) { "Missing icon id $it" } }

        for (id in FreedomIconId.entries) {
            val cmds = FreedomIconPaths.commands(id)
            expect(cmds.isNotEmpty()) { "Icon $id must parse into SVG commands" }
            val p2d = SwingVectorIcons.toPath2D(id)
            val bounds = p2d.bounds2D
            expect(!bounds.isEmpty && bounds.width > 0.0 && bounds.height > 0.0) {
                "Icon $id Path2D bounds must be non-empty, got $bounds"
            }

            val img = java.awt.image.BufferedImage(24, 24, java.awt.image.BufferedImage.TYPE_INT_ARGB)
            val g2 = img.createGraphics()
            g2.color = java.awt.Color(7, 11, 20)
            g2.fillRect(0, 0, 24, 24)
            SwingVectorIcons.asSwingIcon(id, size = 18, color = java.awt.Color(56, 189, 248)).paintIcon(null, g2, 3, 3)
            g2.dispose()

            var litPixels = 0
            for (y in 0 until 24) {
                for (x in 0 until 24) {
                    val c = java.awt.Color(img.getRGB(x, y), true)
                    if (c.blue > 100 || c.green > 80 || c.red > 50) litPixels++
                }
            }
            expect(litPixels >= 4) { "Icon $id rendered too few visible pixels ($litPixels)" }
        }
    }

    // ------------------------------------------------------------------ 41. GlobalCensorshipTelemetry parsers & Turkish summary report
    test("41. GlobalCensorshipTelemetry JSON/trace parsers and Text.telemetryReport formatting") {
        val cf = GlobalCensorshipTelemetry.parseCloudflareTrace(
            "fl=123f\nip=198.51.100.42\nloc=TR\nwarp=plus\ncolo=IST\nsni=plaintext\nhttp=http/2\n",
        )
        expect(cf.ok) { "Cloudflare trace must parse OK" }
        eq(cf.ip, "198.51.100.42", "cf.ip")
        eq(cf.warp, "plus", "cf.warp")
        eq(cf.loc, "TR", "cf.loc")
        eq(cf.colo, "IST", "cf.colo")
        eq(cf.http, "http/2", "cf.http")
        expect(!GlobalCensorshipTelemetry.parseCloudflareTrace("").ok) { "Blank cf trace must report ok=false" }

        val ripe = GlobalCensorshipTelemetry.parseRipeAtlasJson(
            """{"count":42,"results":[{"id":1,"asn_v4":9121},{"id":2,"asn_v4":34984},{"id":3,"asn_v4":9121},{"id":4,"asn_v6":12735}]}""",
            countryCode = "TR",
            queryMs = 55L,
        )
        expect(ripe.ok) { "RIPE summary must parse OK" }
        eq(ripe.connectedCount, 42, "ripe.connectedCount")
        eq(ripe.distinctAsns, 3, "ripe.distinctAsns")
        eq(ripe.sampleAsnNames, listOf("AS9121", "AS34984", "AS12735"), "ripe.sampleAsnNames")

        val ooni = GlobalCensorshipTelemetry.parseOoniJson(
            """
            {
              "results": [
                {"probe_cc":"TR","probe_asn":"AS9121","test_name":"web_connectivity","input":"https://discord.com","anomaly":true,"confirmed":true,"failure":false,"measurement_start_time":"2026-11-14T10:00:00Z"},
                {"probe_cc":"TR","probe_asn":"AS34984","test_name":"web_connectivity","input":"https://wikipedia.org","anomaly":true,"confirmed":false,"failure":false,"measurement_start_time":"2026-11-14T10:01:00Z"},
                {"probe_cc":"TR","probe_asn":"AS12735","test_name":"signal","input":"","anomaly":false,"confirmed":false,"failure":false,"measurement_start_time":"2026-11-14T10:02:00Z"}
              ]
            }
            """.trimIndent(),
        )
        eq(ooni.size, 3, "ooni measurements count")
        expect(ooni[0].confirmed && ooni[0].anomaly && ooni[0].input == "https://discord.com") { "First OONI item mismatch" }
        expect(!ooni[1].confirmed && ooni[1].anomaly) { "Second OONI item mismatch" }
        expect(!ooni[2].confirmed && !ooni[2].anomaly && ooni[2].testName == "signal") { "Third OONI item mismatch" }

        val mlab = GlobalCensorshipTelemetry.parseMlabLocateJson(
            """{"results":[{"machine":"ndt-mlab1-ist01.mlab-oti.measurement-lab.org","city":"Istanbul","country":"TR"}]}""",
            queryMs = 28L,
        )
        expect(mlab.ok) { "M-Lab node must parse OK" }
        eq(mlab.site, "ist01", "mlab.site")
        eq(mlab.city, "Istanbul", "mlab.city")
        expect(!GlobalCensorshipTelemetry.parseMlabLocateJson("""{"results":[]}""", 10L).ok) { "Empty M-Lab results must be ok=false" }

        val okSnap = GlobalTelemetrySnapshot(1L, ripe, ooni, 33L, ooniOk = true, ooniError = "", mlab = mlab, cloudflare = cf)
        val okText = Text.telemetryReport(okSnap)
        expect("RIPE Atlas : 42" in okText && "AS9121" in okText) { "RIPE missing from telemetry report: $okText" }
        expect("[ENGEL]" in okText && "[ANOMALİ]" in okText && "[NORMAL]" in okText) { "OONI tags missing: $okText" }
        expect("M-Lab Düğüm: ndt-mlab1-ist01" in okText && "Cloudflare : IP=198.51.100.42" in okText) { "M-Lab/CF missing: $okText" }

        val errSnap = GlobalTelemetrySnapshot(
            collectedAtMs = 2L,
            ripe = RipeProbeSummary("TR", 0, 0, emptyList(), 0L, ok = false, error = "ağ hatası"),
            ooni = emptyList(),
            ooniQueryMs = 0L,
            ooniOk = false,
            ooniError = "zaman aşımı",
            mlab = MlabServerInfo("", "", "", "", 0L, ok = false, error = "yok"),
            cloudflare = CloudflareTraceInfo("", "", "", "", "", "", ok = false, error = "tls hatası"),
        )
        val errText = Text.telemetryReport(errSnap)
        expect("erişilemedi (ağ hatası)" in errText && "erişilemedi (zaman aşımı)" in errText && "erişilemedi (tls hatası)" in errText) {
            "Error telemetry report incomplete: $errText"
        }
    }

    // ------------------------------------------------------------------ 42. IpPackets HTTP line bounding, Alt-Svc stripping & leak vs persona separation
    test("42. IpPackets bounded HTTP line reader, Alt-Svc h3 response stripper, and persona vs leak accounting") {
        val overlong = ("A".repeat(9000) + "\r\nNEXT_LINE\r\n").toByteArray(Charsets.US_ASCII)
        val bais = java.io.ByteArrayInputStream(overlong)
        val firstLine = IpPackets.readBoundedHttpLine(bais, maxLen = 8192)
        eq(firstLine.length, 8192, "readBoundedHttpLine must cap buffer at 8192 without discarding remainder")
        eq(IpPackets.readBoundedHttpLine(bais, maxLen = 8192), "NEXT_LINE", "Drained remainder allows reading NEXT_LINE cleanly")

        val h3Resp = ("HTTP/1.1 200 OK\r\nServer: test\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nContent-Length: 10\r\n\r\nHELLO_BODY")
            .toByteArray(Charsets.ISO_8859_1)
        val (strippedH3, h3Changed) = IpPackets.stripPlainHttpAltSvc(h3Resp)
        expect(h3Changed) { "Alt-Svc h3 header must be stripped" }
        val h3Text = String(strippedH3, Charsets.ISO_8859_1)
        expect("alt-svc" !in h3Text.lowercase(java.util.Locale.US)) { "Alt-Svc h3 line must be removed: $h3Text" }
        expect("Server: test" in h3Text && h3Text.endsWith("\r\n\r\nHELLO_BODY")) { "Other headers & body must stay intact: $h3Text" }

        val h2OnlyResp = "HTTP/1.1 200 OK\r\nAlt-Svc: h2=\":443\"; ma=86400\r\n\r\nOK".toByteArray(Charsets.ISO_8859_1)
        val (_, h2Changed) = IpPackets.stripPlainHttpAltSvc(h2OnlyResp)
        expect(!h2Changed) { "Non-h3 Alt-Svc must not be flagged as stripped" }

        val tlsBinary = byteArrayOf(0x16, 0x03, 0x03, 0x00, 0x10) + ByteArray(16)
        expect(!IpPackets.stripPlainHttpAltSvc(tlsBinary).second) { "Binary TLS bytes must remain untouched" }

        // Bug #28: Persona spoofing alone must NOT set leakBlocked=true
        val personaOnlyReq = "GET /page?clean=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0 RealOS\r\n\r\n"
            .toByteArray(Charsets.ISO_8859_1)
        val pRes = IpPackets.sanitizePlainHttpHeadersDetailed(
            personaOnlyReq,
            persona = DevicePersona.IPHONE_19_BETA,
            stripGeoHeaders = true,
            stripTrackingParams = true,
        )
        expect(pRes.modified && pRes.personaApplied) { "Persona spoofing should mark modified & personaApplied" }
        expect(!pRes.leakBlocked && !pRes.paramsStripped) { "Persona spoofing alone must not inflate leakBlocked/paramsStripped" }

        val leakReq = "GET /page?utm_source=x&ok=1 HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 203.0.113.5\r\n\r\n"
            .toByteArray(Charsets.ISO_8859_1)
        val lRes = IpPackets.sanitizePlainHttpHeadersDetailed(leakReq, persona = DevicePersona.OFF, stripGeoHeaders = true, stripTrackingParams = true)
        expect(lRes.modified && lRes.leakBlocked && lRes.paramsStripped && !lRes.personaApplied) {
            "XFF + tracking param request must report leakBlocked=true, paramsStripped=true, personaApplied=false"
        }
    }

    // ------------------------------------------------------------------ 43. TunBridge WARP stateful firewall + 32-bit sequence wraparound
    test("43. TunBridge stateful WARP inbound firewall and TcpFlow 32-bit sequence wraparound") {
        DiagnosticSession(fastConfig).use { s ->
            val appToBridgeIn = java.io.PipedInputStream(65536)
            val appToBridgeOut = java.io.PipedOutputStream(appToBridgeIn)
            val bridgeToAppIn = java.io.PipedInputStream(65536)
            val bridgeToAppOut = java.io.PipedOutputStream(bridgeToAppIn)

            fun readNextIp(input: java.io.InputStream): ByteArray {
                val hdr = ByteArray(20)
                var read = 0
                while (read < 20) {
                    val n = input.read(hdr, read, 20 - read)
                    if (n < 0) error("EOF")
                    read += n
                }
                val totalLen = IpPackets.u16(hdr, 2)
                val full = ByteArray(totalLen)
                System.arraycopy(hdr, 0, full, 0, 20)
                while (read < totalLen) {
                    val n = input.read(full, read, totalLen - read)
                    if (n < 0) error("EOF")
                    read += n
                }
                return full
            }

            ServerSocket(0, 8, InetAddress.getLoopbackAddress()).use { echoSrv ->
                echoSrv.soTimeout = 4000
                val sawCleanEofAfterWrap = AtomicBoolean(false)
                val originReceived = AtomicReference("")
                val srvThread = Thread {
                    echoSrv.accept().use { c ->
                        c.soTimeout = 3000
                        val data = c.inputStream.readAllBytes()
                        originReceived.set(String(data, Charsets.US_ASCII))
                        sawCleanEofAfterWrap.set(true)
                        c.outputStream.write("WRAP_OK".toByteArray(Charsets.US_ASCII))
                        c.outputStream.flush()
                    }
                }.apply { isDaemon = true; start() }

                val clientIp = IpPackets.parseIpLiteral(TunBridge.VPN_CLIENT_IP)!!
                val warpIp = IpPackets.parseIpLiteral("172.16.0.2")!!
                val peerIp = IpPackets.parseIpLiteral("93.184.216.34")!!
                val loopbackIp = IpPackets.parseIpLiteral("127.0.0.1")!!

                TunBridge(
                    session = s,
                    tunInput = appToBridgeIn,
                    tunOutput = bridgeToAppOut,
                ).use { bridge ->
                    // 1) Stateful inbound WARP firewall verification
                    val unsolicitedTcp = IpPackets.buildIpv4Tcp(peerIp, warpIp, 443, 55111, 100L, 1L, IpPackets.TCP_SYN or IpPackets.TCP_ACK)
                    val unsolicitedUdp = IpPackets.buildIpv4Udp(peerIp, warpIp, 5353, 55112, byteArrayOf(1, 2, 3, 4))
                    expect(!bridge.isAllowedWarpInbound(unsolicitedTcp)) { "Unsolicited inbound TCP over WARP must be blocked" }
                    expect(!bridge.isAllowedWarpInbound(unsolicitedUdp)) { "Unsolicited inbound UDP over WARP must be blocked" }

                    val outTcp = IpPackets.buildIpv4Tcp(warpIp, peerIp, 55111, 443, 50L, 0L, IpPackets.TCP_SYN)
                    val outUdp = IpPackets.buildIpv4Udp(warpIp, peerIp, 55112, 443, byteArrayOf(9, 8, 7))
                    bridge.recordWarpOutbound(outTcp)
                    bridge.recordWarpOutbound(outUdp)
                    expect(bridge.isAllowedWarpInbound(unsolicitedTcp)) { "Matching tracked inbound TCP over WARP must be allowed" }
                    val matchingUdpReply = IpPackets.buildIpv4Udp(peerIp, warpIp, 443, 55112, byteArrayOf(5, 6))
                    expect(bridge.isAllowedWarpInbound(matchingUdpReply)) { "Matching tracked inbound UDP over WARP must be allowed" }
                    expect(!bridge.isAllowedWarpInbound(unsolicitedUdp)) { "Mismatched srcPort UDP reply must still be rejected" }

                    // 2) TCP 32-bit sequence number wraparound across 0xFFFFFFFFL boundary (0xFFFFFFF8 + 1 (SYN) + 10 (DATA) + 1 (FIN))
                    bridge.start()
                    val iss = 0xFFFFFFF8L
                    appToBridgeOut.write(IpPackets.buildIpv4Tcp(clientIp, loopbackIp, 57123, echoSrv.localPort, iss, 0L, IpPackets.TCP_SYN))
                    appToBridgeOut.flush()
                    val synAck = IpPackets.parseTcp(readNextIp(bridgeToAppIn))!!
                    eq(synAck.ack, 0xFFFFFFF9L, "SYN+ACK ack after iss=0xFFFFFFF8")

                    val payload = "WRAP_12345".toByteArray(Charsets.US_ASCII) // 10 bytes -> next seq = 3L
                    appToBridgeOut.write(
                        IpPackets.buildIpv4Tcp(
                            clientIp, loopbackIp, 57123, echoSrv.localPort,
                            0xFFFFFFF9L, (synAck.seq + 1L) and 0xFFFFFFFFL,
                            IpPackets.TCP_PSH or IpPackets.TCP_ACK, payload = payload,
                        ),
                    )
                    appToBridgeOut.flush()
                    val dataAck = IpPackets.parseTcp(readNextIp(bridgeToAppIn))!!
                    eq(dataAck.ack, 3L, "32-bit wraparound ack must equal 3L")

                    // Client FIN at seq=3L must advance clientNextSeq to 4L and close upstream output so server reads EOF
                    appToBridgeOut.write(
                        IpPackets.buildIpv4Tcp(
                            clientIp, loopbackIp, 57123, echoSrv.localPort,
                            3L, (synAck.seq + 1L) and 0xFFFFFFFFL,
                            IpPackets.TCP_FIN or IpPackets.TCP_ACK,
                        ),
                    )
                    appToBridgeOut.flush()
                    var serverResp = ""
                    var sawFinAck = false
                    for (step in 0 until 6) {
                        val seg = IpPackets.parseTcp(readNextIp(bridgeToAppIn)) ?: continue
                        if (seg.ack == 4L) sawFinAck = true
                        if (seg.payload.isNotEmpty()) serverResp += String(seg.payload, Charsets.US_ASCII)
                        if (sawFinAck && serverResp == "WRAP_OK") break
                    }
                    srvThread.join(2500)
                    expect(sawFinAck) { "FIN after 32-bit wraparound must be ACKed with seq 4L" }
                    expect(sawCleanEofAfterWrap.get()) { "Server must observe clean EOF from wrapped FIN" }
                    eq(originReceived.get(), "WRAP_12345", "Origin must receive exact payload")
                    eq(serverResp, "WRAP_OK", "Client must receive server response after FIN")
                }
            }
        }
    }

    // ------------------------------------------------------------------ 44. WindowsNextGenProxy zero-leak guarantees & live updateSettings
    test("44. WindowsNextGenProxy WARP pre-handshake barrier, CUSTOM_RELAY zero-DNS/fail-closed, live settings & Alt-Svc accounting") {
        // 1) CUSTOM_RELAY zero-DNS leak + fail-closed
        val relayDohCalls = AtomicInteger(0)
        val fakeDoh = object : DohClient {
            override fun post(url: String, body: ByteArray, timeoutMs: Int): DohResponse {
                relayDohCalls.incrementAndGet()
                return DohResponse(1, 100, EncProtocol.DOH, dnsAnswer(body, byteArrayOf(127, 0, 0, 1)))
            }
        }
        val relayTargetSeen = AtomicReference("")
        ServerSocket(0, 8, InetAddress.getLoopbackAddress()).use { origin ->
            origin.soTimeout = 4000
            val originThread = Thread {
                while (!origin.isClosed) {
                    val c = try { origin.accept() } catch (_: Throwable) { break }
                    Thread {
                        c.use { s ->
                            val buf = ByteArray(1024)
                            val n = runCatching { s.inputStream.read(buf) }.getOrDefault(-1)
                            if (n > 0) {
                                s.outputStream.write("RELAY_PONG".toByteArray(Charsets.US_ASCII))
                                s.outputStream.flush()
                            }
                        }
                    }.apply { isDaemon = true; start() }
                }
            }.apply { isDaemon = true; start() }

            ServerSocket(0, 8, InetAddress.getLoopbackAddress()).use { relaySrv ->
                relaySrv.soTimeout = 4000
                val relayThread = Thread {
                    relaySrv.accept().use { c ->
                        val rIn = c.inputStream
                        val sb = StringBuilder()
                        while (!sb.endsWith("\r\n\r\n")) {
                            val ch = rIn.read()
                            if (ch < 0) break
                            sb.append(ch.toChar())
                        }
                        relayTargetSeen.set(sb.toString().lineSequence().firstOrNull().orEmpty())
                        Socket(InetAddress.getLoopbackAddress(), origin.localPort).use { up ->
                            c.outputStream.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray())
                            c.outputStream.flush()
                            val f = Thread { runCatching { rIn.transferTo(up.outputStream); up.shutdownOutput() } }.apply { isDaemon = true; start() }
                            runCatching { up.inputStream.transferTo(c.outputStream); c.outputStream.flush() }
                            f.join(1500)
                        }
                    }
                }.apply { isDaemon = true; start() }

                WindowsNextGenProxy(
                    port = 0,
                    routeMode = WindowsRouteMode.CUSTOM_RELAY,
                    customRelayUri = "http://127.0.0.1:${relaySrv.localPort}",
                    dohClient = fakeDoh,
                    forceDirectForLoopback = false,
                ).use { relayProxy ->
                    val pPort = relayProxy.start()
                    Socket(InetAddress.getLoopbackAddress(), pPort).use { c ->
                        c.soTimeout = 3000
                        c.outputStream.write("CONNECT zero.dns.leak.invalid:${origin.localPort} HTTP/1.1\r\nHost: zero.dns.leak.invalid:${origin.localPort}\r\n\r\n".toByteArray())
                        c.outputStream.flush()
                        val hb = StringBuilder()
                        while (!hb.endsWith("\r\n\r\n")) {
                            val b = c.inputStream.read()
                            if (b < 0) break
                            hb.append(b.toChar())
                        }
                        expect("200" in hb.toString()) { "Relay CONNECT should return 200: $hb" }
                        c.outputStream.write("PING".toByteArray())
                        c.outputStream.flush()
                        val resp = String(c.inputStream.readAllBytes(), Charsets.US_ASCII)
                        eq(resp, "RELAY_PONG", "Traffic should pass through custom HTTP relay")
                    }
                    eq(relayDohCalls.get(), 0, "CUSTOM_RELAY must perform zero local DoH/DNS lookups")
                    eq(relayTargetSeen.get(), "CONNECT zero.dns.leak.invalid:${origin.localPort} HTTP/1.1", "Relay must receive target hostname intact")

                    // Fail-closed when relay URI cleared live
                    relayProxy.updateSettings(customRelayUri = "")
                    expect(!relayProxy.isIpMasked) { "Clearing customRelayUri must mark isIpMasked=false" }
                    Socket(InetAddress.getLoopbackAddress(), pPort).use { c ->
                        c.soTimeout = 2000
                        c.outputStream.write("CONNECT failclosed.invalid:443 HTTP/1.1\r\n\r\n".toByteArray())
                        c.outputStream.flush()
                        val failResp = runCatching { String(c.inputStream.readAllBytes(), Charsets.US_ASCII) }.getOrDefault("")
                        expect("200" !in failResp) { "Fail-closed CUSTOM_RELAY must never return 200 or fall back direct" }
                    }
                    eq(relayDohCalls.get(), 0, "Fail-closed CUSTOM_RELAY must still perform zero DNS lookups")
                }
                relayThread.join(1500)
            }

            // 2) AUTO_WARP pre-handshake barrier (Bug #22)
            val warpEntered = CountDownLatch(1)
            val warpGate = CountDownLatch(1)
            val barrierDohCalls = AtomicInteger(0)
            val barrierDoh = object : DohClient {
                override fun post(url: String, body: ByteArray, timeoutMs: Int): DohResponse {
                    barrierDohCalls.incrementAndGet()
                    return DohResponse(1, 50, EncProtocol.DOH, dnsAnswer(body, byteArrayOf(127, 0, 0, 1)))
                }
            }
            val fakeWarpId = WarpIdentity(
                privateKeyB64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                peerPublicKeyB64 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                clientIpv4 = "172.16.0.2",
                endpointHost = "127.0.0.1",
                endpointPort = 2408,
            )
            WindowsNextGenProxy(
                port = 0,
                routeMode = WindowsRouteMode.AUTO_WARP,
                dohEndpoints = listOf("https://1.1.1.1/dns-query"),
                dohClient = barrierDoh,
                warpIdentityOverride = fakeWarpId,
                warpFactory = { id ->
                    warpEntered.countDown()
                    warpGate.await(3000, java.util.concurrent.TimeUnit.MILLISECONDS)
                    // Close immediately so WarpTunnel.connect exits instantaneously without sleeping 3.2s
                    WarpTunnel(id).apply { close() }
                },
                forceDirectForLoopback = false,
                allowLoopbackDns = true,
            ).use { warpProxy ->
                val wPort = warpProxy.start()
                expect(warpEntered.await(2000, java.util.concurrent.TimeUnit.MILLISECONDS)) { "bootstrapAutoWarp must enter warpFactory" }
                val clientDone = CountDownLatch(1)
                val clientBanner = AtomicReference("")
                val clientThread = Thread {
                    runCatching {
                        Socket(InetAddress.getLoopbackAddress(), wPort).use { c ->
                            c.soTimeout = 4000
                            c.outputStream.write("CONNECT barrier.example:${origin.localPort} HTTP/1.1\r\nHost: barrier.example:${origin.localPort}\r\n\r\n".toByteArray())
                            c.outputStream.flush()
                            val hb = StringBuilder()
                            while (!hb.endsWith("\r\n\r\n")) {
                                val b = c.inputStream.read()
                                if (b < 0) break
                                hb.append(b.toChar())
                            }
                            clientBanner.set(hb.toString())
                        }
                    }
                    clientDone.countDown()
                }.apply { isDaemon = true; start() }

                Thread.sleep(160)
                eq(barrierDohCalls.get(), 0, "Zero DNS lookups may execute while AUTO_WARP handshake is bootstrapping")
                expect(clientDone.count > 0L) { "Client connection must be held by pre-handshake barrier until WARP settles" }

                warpGate.countDown()
                expect(clientDone.await(3500, java.util.concurrent.TimeUnit.MILLISECONDS)) { "Client must proceed immediately once WARP settles" }
                clientThread.join(1000)
                expect("200" in clientBanner.get()) { "Fallback after WARP barrier should succeed: ${clientBanner.get()}" }
                expect(barrierDohCalls.get() >= 1) { "DoH resolves only after WARP bootstrap settles" }
            }

            // 3) Bug #25 live updateSettings & Bug #28 Alt-Svc stripping / persona-only leak accounting
            val upstreamRequests = java.util.Collections.synchronizedList(ArrayList<String>())
            val sendAltSvc = AtomicBoolean(true)
            ServerSocket(0, 8, InetAddress.getLoopbackAddress()).use { httpSrv ->
                httpSrv.soTimeout = 4000
                val httpThread = Thread {
                    while (!httpSrv.isClosed) {
                        val c = try { httpSrv.accept() } catch (_: Throwable) { break }
                        Thread {
                            c.use { s ->
                                s.soTimeout = 2000
                                val sb = StringBuilder()
                                while (!sb.endsWith("\r\n\r\n")) {
                                    val ch = s.inputStream.read()
                                    if (ch < 0) break
                                    sb.append(ch.toChar())
                                }
                                upstreamRequests.add(sb.toString())
                                val altHdr = if (sendAltSvc.get()) "Alt-Svc: h3=\":443\"; ma=86400\r\n" else ""
                                s.outputStream.write(("HTTP/1.1 200 OK\r\n${altHdr}Content-Length: 2\r\nConnection: close\r\n\r\nOK").toByteArray())
                                s.outputStream.flush()
                            }
                        }.apply { isDaemon = true; start() }
                    }
                }.apply { isDaemon = true; start() }

                WindowsNextGenProxy(
                    port = 0,
                    routeMode = WindowsRouteMode.HYBRID_DPI,
                    persona = DevicePersona.IPHONE_19_BETA,
                    blockTrackers = true,
                    stripUrlParams = true,
                    blockQuicAndLeaks = true,
                    dohEndpoints = listOf("https://1.1.1.1/dns-query"),
                    dohClient = fakeDoh,
                    allowLoopbackDns = true,
                ).use { proxy ->
                    val pPort = proxy.start()

                    // Request A: Persona spoofing with Alt-Svc=off -> leaksBlocked stays 0 (Bug #28)
                    sendAltSvc.set(false)
                    Socket(InetAddress.getLoopbackAddress(), pPort).use { s ->
                        s.soTimeout = 3000
                        s.outputStream.write("GET http://127.0.0.1:${httpSrv.localPort}/a?keep=1 HTTP/1.1\r\nHost: 127.0.0.1:${httpSrv.localPort}\r\nUser-Agent: RealClient\r\n\r\n".toByteArray())
                        s.outputStream.flush()
                        val resp = String(s.inputStream.readAllBytes(), Charsets.US_ASCII)
                        expect(resp.endsWith("OK")) { "Plain HTTP persona request failed: $resp" }
                    }
                    eq(proxy.leaksBlocked.get(), 0L, "Persona UA rewrite alone must not increment leaksBlocked")
                    expect("iPhone19,3" in upstreamRequests.last()) { "Persona should be applied on request A" }

                    // Request B: Response contains Alt-Svc: h3 -> stripped before client & leaksBlocked == 1
                    sendAltSvc.set(true)
                    Socket(InetAddress.getLoopbackAddress(), pPort).use { s ->
                        s.soTimeout = 3000
                        s.outputStream.write("GET http://127.0.0.1:${httpSrv.localPort}/b HTTP/1.1\r\nHost: 127.0.0.1:${httpSrv.localPort}\r\nUser-Agent: RealClient\r\n\r\n".toByteArray())
                        s.outputStream.flush()
                        val resp = String(s.inputStream.readAllBytes(), Charsets.US_ASCII)
                        expect("alt-svc" !in resp.lowercase(java.util.Locale.US) && resp.endsWith("OK")) {
                            "Alt-Svc h3 must be stripped from plain HTTP response: $resp"
                        }
                    }
                    eq(proxy.leaksBlocked.get(), 1L, "Alt-Svc h3 response strip must increment leaksBlocked to 1")

                    // Tracker domain is blocked with 403 while blockTrackers=true
                    Socket(InetAddress.getLoopbackAddress(), pPort).use { s ->
                        s.soTimeout = 3000
                        s.outputStream.write("GET http://doubleclick.net:${httpSrv.localPort}/blocked HTTP/1.1\r\nHost: doubleclick.net:${httpSrv.localPort}\r\n\r\n".toByteArray())
                        s.outputStream.flush()
                        val resp = String(s.inputStream.readAllBytes(), Charsets.US_ASCII)
                        expect("403 Forbidden" in resp) { "Tracker domain must return 403 while blockTrackers=true: $resp" }
                    }

                    // Bug #25: Live settings update toggles tracker blocking, param stripping, persona, and Alt-Svc off
                    proxy.updateSettings(
                        blockTrackers = false,
                        stripUrlParams = false,
                        blockQuicAndLeaks = false,
                        devicePersona = DevicePersona.OFF,
                    )
                    Socket(InetAddress.getLoopbackAddress(), pPort).use { s ->
                        s.soTimeout = 3000
                        s.outputStream.write("GET http://127.0.0.1:${httpSrv.localPort}/c?utm_source=keepme HTTP/1.1\r\nHost: 127.0.0.1:${httpSrv.localPort}\r\nUser-Agent: KeepOriginalUA\r\n\r\n".toByteArray())
                        s.outputStream.flush()
                        val resp = String(s.inputStream.readAllBytes(), Charsets.US_ASCII)
                        expect("Alt-Svc: h3=" in resp) { "Alt-Svc must be preserved when blockQuicAndLeaks=false: $resp" }
                    }
                    expect("utm_source=keepme" in upstreamRequests.last() && "KeepOriginalUA" in upstreamRequests.last()) {
                        "Live updateSettings must disable URL param stripping & UA spoofing: ${upstreamRequests.last()}"
                    }

                    // Tracker domain succeeds over loopback once live blockTrackers=false (resolved via fakeDoh -> 127.0.0.1)
                    Socket(InetAddress.getLoopbackAddress(), pPort).use { s ->
                        s.soTimeout = 3000
                        s.outputStream.write("GET http://doubleclick.net:${httpSrv.localPort}/allowed HTTP/1.1\r\nHost: doubleclick.net:${httpSrv.localPort}\r\n\r\n".toByteArray())
                        s.outputStream.flush()
                        val resp = String(s.inputStream.readAllBytes(), Charsets.US_ASCII)
                        expect("200 OK" in resp && "403 Forbidden" !in resp) { "Tracker domain must succeed via loopback once blockTrackers=false: $resp" }
                    }
                }
                httpSrv.close()
                httpThread.join(1000)
            }
            origin.close()
            originThread.join(1000)
        }
    }

    // ------------------------------------------------------------------ 45. Unhovered Swing anti-white hardening, ComboBox/CheckBox/4 workspaces, formatting & Sanitizer
    test("45. Unhovered Swing controls, JComboBox, all 4 MainWindow workspaces, Sparkline/Shield visuals & WindowsSystemProxy sanitizer") {
        // 1) WindowsSystemProxy loop/stale localhost sanitization
        eq(WindowsSystemProxy.sanitizeCapturedProxy(1, "127.0.0.1:8880"), 0 to null, "Loopback proxy sanitized")
        eq(WindowsSystemProxy.sanitizeCapturedProxy(1, "http=127.0.0.1:8880;https=127.0.0.1:8880"), 0 to null, "Scheme loopback sanitized")
        eq(WindowsSystemProxy.sanitizeCapturedProxy(1, "localhost:9999"), 0 to null, "localhost proxy sanitized")
        eq(WindowsSystemProxy.sanitizeCapturedProxy(1, "corp-proxy.local:8080"), 1 to "corp-proxy.local:8080", "External proxy preserved")
        eq(WindowsSystemProxy.sanitizeCapturedProxy(0, "corp-proxy.local:8080"), 0 to null, "Disabled proxy stays off")

        // 2) ThroughputSparklinePanel unit formatting (B/s .. GB/s and B .. GB)
        val sp = ThroughputSparklinePanel()
        expect("B/s" in sp.formatRate(0.25f) && "KB/s" !in sp.formatRate(0.25f)) { "Sub-KB/s must format as B/s" }
        expect("KB/s" in sp.formatRate(42.5f)) { "KB/s range format check" }
        expect("MB/s" in sp.formatRate(2048f)) { "MB/s range format check" }
        expect("GB/s" in sp.formatRate(2_097_152f)) { "GB/s range format check" }
        eq(sp.formatBytes(512L), "512 B", "formatBytes B")
        expect("KB" in sp.formatBytes(2048L) && "MB" in sp.formatBytes(5L * 1024L * 1024L) && "GB" in sp.formatBytes(3L * 1024L * 1024L * 1024L)) {
            "formatBytes scaling check"
        }

        // 3) ModernPowerShieldPanel isConnecting state offscreen paint + animator offscreen safety
        val shield = ModernPowerShieldPanel().apply {
            setSize(320, 180)
            isConnecting = true
        }
        val shieldImg = java.awt.image.BufferedImage(320, 180, java.awt.image.BufferedImage.TYPE_INT_ARGB)
        val sg = shieldImg.createGraphics()
        shield.paint(sg)
        sg.dispose()
        shield.stop()
        var amberPixels = 0
        for (y in 0 until 180) {
            for (x in 0 until 320) {
                val c = java.awt.Color(shieldImg.getRGB(x, y), true)
                if (c.red > 180 && c.green in 110..235 && c.blue < 120) amberPixels++
            }
        }
        expect(amberPixels >= 25) { "isConnecting state must render visible amber aura/emblem pixels, got $amberPixels" }

        // 4) Unhovered FreedomButton (text+icon & icon-only) & JComboBox offscreen pixel visibility (never white/hover-only)
        FreedomDarkTheme.install()
        expect(javax.swing.UIManager.get("Button.gradient") == null) { "Metal OceanTheme Button.gradient must be cleared" }

        fun assertDarkWithBrightGlyphs(img: java.awt.image.BufferedImage, label: String) {
            var darkPx = 0
            var glyphPx = 0
            var whiteBgPx = 0
            for (y in 0 until img.height) {
                for (x in 0 until img.width) {
                    val c = java.awt.Color(img.getRGB(x, y), true)
                    if (c.red < 55 && c.green < 65 && c.blue < 90) darkPx++
                    if (c.red > 130 || c.green > 130 || c.blue > 130) glyphPx++
                    if (c.red > 240 && c.green > 240 && c.blue > 240) whiteBgPx++
                }
            }
            val total = img.width * img.height
            expect(darkPx > total * 0.55) { "$label must keep dark background (>=55%), got $darkPx/$total" }
            expect(glyphPx >= 18) { "$label must visibly paint foreground/icon pixels BEFORE hover, got $glyphPx" }
            expect(whiteBgPx < total * 0.12) { "$label must never fill a bright white box, got $whiteBgPx/$total" }
        }

        val unhoveredBtn = FreedomButton("ÖZGÜR AĞ", iconDrawer = SwingVectorIcons::drawPower).apply { setSize(160, 36) }
        val btnImg = java.awt.image.BufferedImage(160, 36, java.awt.image.BufferedImage.TYPE_INT_ARGB)
        unhoveredBtn.createGraphicsSafePaint(btnImg)
        assertDarkWithBrightGlyphs(btnImg, "Unhovered FreedomButton")

        val arrowOnlyBtn = FreedomButton(
            "",
            fillColor = java.awt.Color(23, 34, 54),
            textColor = java.awt.Color(148, 163, 184),
            borderColor = java.awt.Color(38, 52, 74),
            arc = 6,
            iconDrawer = { g2, cx, cy, sz, col -> SwingVectorIcons.drawIcon(g2, FreedomIconId.CHEVRON_DOWN, cx, cy, sz, col, 2.0f) },
        ).apply { setSize(28, 28) }
        val arrImg = java.awt.image.BufferedImage(28, 28, java.awt.image.BufferedImage.TYPE_INT_ARGB)
        arrowOnlyBtn.createGraphicsSafePaint(arrImg)
        assertDarkWithBrightGlyphs(arrImg, "Unhovered Icon-only FreedomButton")

        val combo = FreedomDarkTheme.styleCombo(javax.swing.JComboBox(arrayOf("Google Chrome", "Microsoft Edge"))).apply {
            setSize(240, 32)
            doLayout()
        }
        val comboImg = java.awt.image.BufferedImage(240, 32, java.awt.image.BufferedImage.TYPE_INT_ARGB)
        combo.createGraphicsSafePaint(comboImg)
        assertDarkWithBrightGlyphs(comboImg, "Unhovered styled JComboBox")

        // 5) Paint all 4 MainWindow workspaces & confirm no white chrome & live telemetry card exists in Diagnostics tab
        val win = MainWindow()
        try {
            val root = win.buildRootPanelForTest()
            root.setSize(1080, 760)
            root.doLayout()

            val navBtns = ArrayList<FreedomButton>()
            val textAreas = ArrayList<javax.swing.JTextArea>()
            fun walk(c: java.awt.Component) {
                if (c is FreedomButton) navBtns += c
                if (c is javax.swing.JTextArea) textAreas += c
                if (c is java.awt.Container) c.components.forEach(::walk)
            }
            walk(root)
            val tabButtons = navBtns.filter {
                it.text in setOf("Kontrol Merkezi", "Tarayıcı & Gizlilik", "Ağ Teşhis Lab", "Sistem & Günlük")
            }
            eq(tabButtons.size, 4, "MainWindow must expose all 4 sidebar workspace buttons")
            expect(textAreas.any { "RIPE Atlas" in it.text }) {
                "Diagnostics workspace must embed live RIPE Atlas / OONI / M-Lab telemetry area"
            }

            for ((idx, tabBtn) in tabButtons.withIndex()) {
                tabBtn.doClick()
                root.doLayout()
                val wsImg = java.awt.image.BufferedImage(1080, 760, java.awt.image.BufferedImage.TYPE_INT_ARGB)
                root.createGraphicsSafePaint(wsImg)
                // Bottom-right and center-top edges across every workspace must remain dark obsidian
                val corner = java.awt.Color(wsImg.getRGB(1065, 745), true)
                val navEdge = java.awt.Color(wsImg.getRGB(10, 360), true)
                expect(corner.red < 45 && corner.green < 45 && corner.blue < 70) {
                    "Workspace $idx (${tabBtn.text}) bottom-right leaked bright color: $corner"
                }
                expect(navEdge.red < 45 && navEdge.green < 45 && navEdge.blue < 70) {
                    "Workspace $idx sidebar edge leaked bright color: $navEdge"
                }
            }
        } finally {
            win.shutdown()
        }
    }

    // ------------------------------------------------------------------ 46. runCli --self-test end-to-end gate
    test("46. runCli --self-test passes all native, icon, telemetry, sanitizer and proxy checks") {
        eq(runCli(listOf("--self-test")), 0, "runCli --self-test must pass and exit 0")
    }

    println()
    println("RESULT: $passed passed, ${failures.size} failed")
    if (failures.isNotEmpty()) {
        failures.forEach { println("  failed: $it") }
        exitProcess(1)
    }
    exitProcess(0)
}

private fun java.awt.Component.createGraphicsSafePaint(img: java.awt.image.BufferedImage) {
    val g2 = img.createGraphics()
    this.paint(g2)
    g2.dispose()
}

