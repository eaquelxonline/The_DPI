// Freedom Network — Windows 10/11 x64 application (Kotlin/JVM, JDK Swing, Rust DLL via JNI).
//
// Self-contained: the JNI boundary (class com.freedom.network.Native), the wire codec mirrored from
// Native/Core.rs, typed models, the platform-TLS prober, the diagnostic session
// orchestrator, the Turkish text catalogue, and this platform's integration.
// The shared section below is kept byte-identical with the other platform module.

package com.freedom.network

import java.time.Duration
import java.net.http.HttpTimeoutException
import java.net.http.HttpResponse
import java.net.http.HttpRequest
import java.net.http.HttpClient
import java.net.URI
import java.net.ProxySelector
import java.net.ConnectException
import java.awt.BasicStroke
import java.awt.CardLayout
import java.awt.Cursor
import java.awt.LinearGradientPaint
import java.awt.RadialGradientPaint
import java.awt.datatransfer.StringSelection
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.awt.geom.Path2D
import java.awt.geom.RoundRectangle2D
import java.awt.geom.Arc2D
import java.awt.geom.Ellipse2D
import java.awt.geom.Line2D
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.Font
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.GridLayout
import java.awt.Insets
import java.awt.RenderingHints
import java.awt.Toolkit
import java.awt.event.WindowAdapter
import java.awt.event.WindowEvent
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.PushbackInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.locks.ReentrantLock
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.nio.channels.SocketChannel
import java.nio.channels.DatagramChannel
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.security.KeyStore
import java.security.cert.CertPathValidatorException
import java.security.cert.CertificateException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSession
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.imageio.ImageIO
import javax.swing.BorderFactory
import javax.swing.BoxLayout
import javax.swing.Icon
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.ScrollPaneConstants
import javax.swing.SwingConstants
import javax.swing.SwingUtilities
import javax.swing.Timer
import javax.swing.UIManager
import javax.swing.WindowConstants
import javax.swing.plaf.basic.BasicScrollBarUI
import java.awt.event.HierarchyEvent
import java.awt.event.HierarchyListener
import java.security.SecureRandom
import javax.swing.plaf.basic.BasicButtonUI
import javax.swing.plaf.basic.BasicComboBoxUI
import javax.swing.plaf.basic.BasicComboPopup
import javax.swing.plaf.basic.ComboPopup
import kotlin.system.exitProcess

// ==================================================================================
// SHARED SECTION — identical in Android/Core.kt and Windows/Core.kt. Edit both together.
// ==================================================================================

// ------------------------------------------------------------------ JNI

/** The single JNI boundary. Symbols: Java_com_freedom_network_Native_* in Native/Core.rs. */
object Native {
    const val EXPECTED_API = 1
    const val LIBRARY = "freedom"

    /** Null when the native library loaded; otherwise the reason it did not. */
    val loadError: Throwable? = try {
        System.loadLibrary(LIBRARY)
        null
    } catch (e: UnsatisfiedLinkError) {
        e
    } catch (e: SecurityException) {
        e
    } catch (t: Throwable) {
        t
    }

    val available: Boolean get() = loadError == null

    @JvmStatic external fun apiVersion(): Int
    @JvmStatic external fun engineVersion(): String?
    @JvmStatic external fun create(config: ByteArray?): Long
    @JvmStatic external fun destroy(handle: Long): Int
    @JvmStatic external fun detectEnvironment(): ByteArray?
    @JvmStatic external fun setEnvironment(handle: Long, env: ByteArray): Int
    @JvmStatic external fun diagnose(handle: Long, request: ByteArray): ByteArray?
    @JvmStatic external fun submitTls(handle: Long, observations: ByteArray): Int
    @JvmStatic external fun evaluate(handle: Long): ByteArray?
    @JvmStatic external fun networkChanged(handle: Long): Int
    @JvmStatic external fun markApplied(handle: Long, action: Int): Int
    @JvmStatic external fun dohQuery(request: ByteArray): ByteArray?
    @JvmStatic external fun systemConnections(): ByteArray?
    @JvmStatic external fun submitEncrypted(handle: Long, results: ByteArray): Int
    @JvmStatic external fun desyncPacket(handle: Long, request: ByteArray): ByteArray?
    @JvmStatic external fun startProxy(handle: Long, config: ByteArray): ByteArray?
    @JvmStatic external fun stopProxy(handle: Long): Int
    @JvmStatic external fun proxyStats(handle: Long): ByteArray?
    @JvmStatic external fun wgPublicKey(privKey: ByteArray): ByteArray?
    @JvmStatic external fun wgCreate(privKey: ByteArray, peerPub: ByteArray): Long
    @JvmStatic external fun wgDestroy(wgHandle: Long): Int
    @JvmStatic external fun wgHandshakeInit(wgHandle: Long, ephPriv: ByteArray, tai64n12: ByteArray): ByteArray?
    @JvmStatic external fun wgConsumeResponse(wgHandle: Long, pkt: ByteArray): Int
    @JvmStatic external fun wgEncrypt(wgHandle: Long, ipPacket: ByteArray): ByteArray?
    @JvmStatic external fun wgDecrypt(wgHandle: Long, wgPacket: ByteArray): ByteArray?
    @JvmStatic external fun wgSetReserved(wgHandle: Long, reserved3: ByteArray): Int
    @JvmStatic external fun wgBuildAwgPrefaces(jc: Int, jmin: Int, jmax: Int, cpsTemplate: ByteArray?): ByteArray?
}

object Codes {
    const val OK = 0
    const val INVALID_ARGUMENT = -1
    const val INVALID_HANDLE = -2
    const val WIRE = -3
    const val BUSY = -4
    const val LIMIT = -5
    const val PANIC = -6
    const val NO_ENVIRONMENT = -7
    const val NO_DATA = -8
    const val UNSUPPORTED = -9
    const val JNI = -10
    const val INTERNAL = -11
}

class NativeException(val code: Int, message: String) : Exception(message)

// ------------------------------------------------------------------ wire codec

/** Mirror of `wire` in Native/Core.rs: "DP", version 1, fields (tag u8, kind u8, len u32 BE, payload). */
class Record {
    sealed interface Value
    data class IntValue(val v: Long) : Value
    data class TextValue(val v: String) : Value
    data class RecordValue(val v: Record) : Value
    class BytesValue(val v: ByteArray) : Value {
        override fun equals(other: Any?) = other is BytesValue && other.v.contentEquals(v)
        override fun hashCode() = v.contentHashCode()
    }

    val fields = ArrayList<Pair<Int, Value>>()

    fun int(tag: Int, v: Long) = apply { fields += tag to IntValue(v) }
    fun int(tag: Int, v: Int) = int(tag, v.toLong())
    fun text(tag: Int, v: String) = apply { fields += tag to TextValue(Wire.truncateUtf8(v, Wire.MAX_TEXT)) }
    fun record(tag: Int, r: Record) = apply { fields += tag to RecordValue(r) }
    fun bytes(tag: Int, v: ByteArray) = apply { fields += tag to BytesValue(v.copyOf(minOf(v.size, Wire.MAX_BYTES))) }
    fun getBytes(tag: Int): ByteArray? = fields.firstOrNull { it.first == tag && it.second is BytesValue }?.let { (it.second as BytesValue).v }

    fun ints(tag: Int): List<Long> = fields.filter { it.first == tag }.mapNotNull { (it.second as? IntValue)?.v }
    fun texts(tag: Int): List<String> = fields.filter { it.first == tag }.mapNotNull { (it.second as? TextValue)?.v }
    fun records(tag: Int): List<Record> = fields.filter { it.first == tag }.mapNotNull { (it.second as? RecordValue)?.v }
    fun bytesAll(tag: Int): List<ByteArray> = fields.filter { it.first == tag }.mapNotNull { (it.second as? BytesValue)?.v }
    fun getInt(tag: Int): Long? = ints(tag).firstOrNull()
    fun getText(tag: Int): String? = texts(tag).firstOrNull()
    val status: Long? get() = getInt(Tags.STATUS)

    override fun equals(other: Any?) = other is Record && other.fields == fields
    override fun hashCode() = fields.hashCode()
}

class WireException(message: String) : Exception(message)

object Wire {
    const val VERSION = 1
    const val MAX_MESSAGE = 256 * 1024
    const val MAX_DEPTH = 4
    const val MAX_FIELDS = 8192
    const val MAX_TEXT = 4096
    private const val KIND_INT = 1
    private const val KIND_TEXT = 2
    private const val KIND_RECORD = 3
    private const val KIND_BYTES = 4
    const val MAX_BYTES = 16 * 1024

    fun truncateUtf8(s: String, max: Int): String {
        val bytes = s.toByteArray(Charsets.UTF_8)
        if (bytes.size <= max) return s
        var end = max
        while (end > 0 && (bytes[end].toInt() and 0xC0) == 0x80) end-- // never split a code point
        return String(bytes, 0, end, Charsets.UTF_8)
    }

    fun encode(r: Record): ByteArray {
        val out = ByteArrayOutputStream(256)
        out.write('D'.code); out.write('P'.code); out.write(VERSION)
        val count = IntArray(1)
        encodeFields(r, out, 0, count)
        if (out.size() > MAX_MESSAGE) throw WireException("message too large")
        return out.toByteArray()
    }

    private fun header(out: ByteArrayOutputStream, tag: Int, kind: Int, len: Int) {
        require(tag in 0..255) { "tag out of range" }
        out.write(tag); out.write(kind)
        out.write(ByteBuffer.allocate(4).putInt(len).array())
    }

    private fun encodeFields(r: Record, out: ByteArrayOutputStream, depth: Int, count: IntArray) {
        if (depth >= MAX_DEPTH) throw WireException("too deep")
        for ((tag, v) in r.fields) {
            if (++count[0] > MAX_FIELDS) throw WireException("too many fields")
            when (v) {
                is Record.IntValue -> {
                    header(out, tag, KIND_INT, 8)
                    out.write(ByteBuffer.allocate(8).putLong(v.v).array())
                }
                is Record.TextValue -> {
                    val b = v.v.toByteArray(Charsets.UTF_8)
                    header(out, tag, KIND_TEXT, b.size)
                    out.write(b)
                }
                is Record.BytesValue -> {
                    header(out, tag, KIND_BYTES, v.v.size)
                    out.write(v.v)
                }
                is Record.RecordValue -> {
                    val inner = ByteArrayOutputStream()
                    encodeFields(v.v, inner, depth + 1, count)
                    header(out, tag, KIND_RECORD, inner.size())
                    inner.writeTo(out)
                }
            }
            if (out.size() > MAX_MESSAGE) throw WireException("message too large")
        }
    }

    fun decode(b: ByteArray): Record {
        if (b.size > MAX_MESSAGE) throw WireException("message too large")
        if (b.size < 3) throw WireException("truncated")
        if (b[0] != 'D'.code.toByte() || b[1] != 'P'.code.toByte()) throw WireException("bad magic")
        if (b[2].toInt() != VERSION) throw WireException("bad version")
        return decodeFields(ByteBuffer.wrap(b, 3, b.size - 3).slice(), 0, IntArray(1))
    }

    private fun decodeFields(buf: ByteBuffer, depth: Int, count: IntArray): Record {
        if (depth >= MAX_DEPTH) throw WireException("too deep")
        val rec = Record()
        while (buf.hasRemaining()) {
            if (buf.remaining() < 6) throw WireException("truncated header")
            val tag = buf.get().toInt() and 0xFF
            val kind = buf.get().toInt() and 0xFF
            val len = buf.int.toLong() and 0xFFFFFFFFL
            if (len > buf.remaining()) throw WireException("truncated payload")
            if (++count[0] > MAX_FIELDS) throw WireException("too many fields")
            val payload = buf.slice().limit(len.toInt()) as ByteBuffer
            buf.position(buf.position() + len.toInt())
            val value: Record.Value = when (kind) {
                KIND_INT -> {
                    if (len != 8L) throw WireException("bad int length")
                    Record.IntValue(payload.long)
                }
                KIND_TEXT -> {
                    if (len > MAX_TEXT) throw WireException("text too long")
                    val decoder = Charsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                    try {
                        Record.TextValue(decoder.decode(payload).toString())
                    } catch (e: CharacterCodingException) {
                        throw WireException("bad utf-8")
                    }
                }
                KIND_RECORD -> Record.RecordValue(decodeFields(payload, depth + 1, count))
                KIND_BYTES -> {
                    if (len > MAX_BYTES) throw WireException("bytes too long")
                    Record.BytesValue(ByteArray(len.toInt()).also { payload.get(it) })
                }
                else -> throw WireException("bad kind $kind")
            }
            rec.fields += tag to value
        }
        return rec
    }
}

/** Field tags; mirror of `tags` in Native/Core.rs. */
object Tags {
    const val STATUS = 0

    object Config {
        const val TIMEOUT_MS = 1; const val DNS_SAMPLES = 2; const val MAX_PARALLEL = 3; const val COOLDOWN_MS = 4
        const val HYSTERESIS_PCT = 5; const val QUIC = 6; const val MTU = 7; const val TCP_SAMPLES = 8; const val BUDGET_MS = 9
    }

    object Env {
        const val OS_NAME = 1; const val OS_VERSION = 2; const val ARCH = 3; const val NETWORK_TYPE = 4; const val INTERFACE = 5
        const val DNS_SERVER = 6; const val GATEWAY = 7; const val MTU = 8; const val HAS_IPV4 = 9; const val HAS_IPV6 = 10
        const val CAPTIVE = 11; const val METERED = 12; const val VALIDATED = 13; const val PRIVATE_DNS = 14
        const val PRIVATE_DNS_NAME = 15; const val OS_BUILD = 16; const val CONNECTED = 17; const val RESTRICT_BACKGROUND = 18
    }

    object Request { const val TARGET = 1; const val ALT_DNS = 2 }

    object Run { const val GENERATION = 1; const val DURATION_US = 2; const val RESOLVER = 3; const val TARGET = 4; const val INVALID = 5; const val ENCRYPTED = 6 }

    object Resolver {
        const val SERVER = 1; const val ALTERNATE = 2; const val SENT = 3; const val RECEIVED = 4
        const val AVG_US = 5; const val JITTER_US = 6; const val STATUS = 7; const val TCP_STATUS = 8
    }

    object Target {
        const val HOST = 1; const val PORT = 2; const val DNS_STATUS = 3; const val DNS_US = 4; const val ADDRESS = 5
        const val HTTPS_RR = 6; const val ALPN = 7; const val ECH = 8; const val TCP4_STATUS = 9; const val TCP4_US = 10
        const val TCP6_STATUS = 11; const val TCP6_US = 12; const val QUIC_STATUS = 13; const val QUIC_US = 14
        const val QUIC_VERSION = 15; const val PMTU = 16; const val MTU_STATUS = 17; const val TLS_STATUS = 18
        const val TLS_US = 19; const val TLS_VERSION = 20; const val TLS_ALPN = 21; const val TLS_CIPHER = 22
        const val TCP4_ATTEMPTS = 23; const val TCP4_OK = 24; const val TCP6_ATTEMPTS = 25; const val TCP6_OK = 26
        const val MTU_PROBES = 27; const val DNS_SERVER = 28; const val DNS_TCP = 29; const val DNS_RCODE = 30
        const val LITERAL = 31; const val MTU_CEILING = 32
    }

    object TlsSubmit { const val RESULT = 1 }
    object EncSubmit { const val RESULT = 1 }
    object Enc {
        const val ENDPOINT = 1; const val PROTOCOL = 2; const val TRANSPORT = 3; const val RTT_US = 4
        const val QUERY_NAME = 5; const val QTYPE = 6; const val RESPONSE = 7; const val STATUS = 8; const val ANSWERS = 9
    }
    object DohQuery { const val NAME = 1; const val QTYPE = 2; const val QUERY = 1 }
    object Sysnet {
        const val TOTAL = 1; const val ESTABLISHED = 2; const val LISTEN = 3; const val SYN_SENT = 4; const val TIME_WAIT = 5
        const val CLOSE_WAIT = 6; const val UDP = 7; const val PROCESS = 8; const val FINDING = 9; const val EXPOSED = 10; const val OS_ERROR = 11
    }
    object Process {
        const val PID = 1; const val NAME = 2; const val ESTABLISHED = 3; const val SYN_SENT = 4; const val LISTEN = 5
        const val UDP = 6; const val REMOTES = 7; const val CLOSE_WAIT = 8; const val SAMPLE = 9
    }
    object Finding { const val CODE = 1; const val SUBJECT = 2; const val ARG = 3 }

    object Tls {
        const val HOST = 1; const val PORT = 2; const val STATUS = 3; const val HANDSHAKE_US = 4
        const val VERSION = 5; const val ALPN = 6; const val CIPHER = 7
    }

    object Eval { const val SCORE = 1; const val EWMA = 2; const val GENERATION = 3; const val DIAGNOSIS = 4; const val DECISION = 5; const val STABILITY = 6; const val EVALUATIONS = 7; const val DESYNC_MODE = 8 }
    object Diagnosis { const val CATEGORY = 1; const val CONFIDENCE = 2; const val OBSERVATION = 3 }
    object Observation { const val CODE = 1; const val SUBJECT = 2; const val ARG = 3 }
    object Decision { const val STATE = 1; const val ACTION = 2; const val CONFIDENCE = 3; const val CATEGORY = 4; const val COOLDOWN_MS = 5; const val PARAM = 6; const val HIGH_IMPACT = 7 }
    object Desync {
        const val MODE = 1; const val FAKE_TTL = 2; const val SPLIT_POS = 3; const val DROP_RST = 4
        const val PORT = 5; const val PACKET = 6; const val OUT_PACKET = 7; const val DROPPED = 8
        const val PROTOCOL = 9; const val SNI = 10; const val ECH = 11; const val POST_QUANTUM = 12
        const val CONNECTIONS = 13; const val TLS_SPLIT = 14; const val HTTP_SPLIT = 15
        const val FAKE_SENT = 16; const val RST_DROPPED = 17; const val ACTIVE = 18
        const val VISION_SPLICE = 19; const val REALITY_DEST = 20
        const val PERSONA = 21; const val BLOCK_TRACKERS = 22; const val STRIP_PARAMS = 23
        const val TRACKERS_BLOCKED = 24; const val PARAMS_STRIPPED = 25
    }
}

// ------------------------------------------------------------------ models

const val NO = 0
const val YES = 1
const val UNKNOWN = 2

object NetworkType { const val UNKNOWN = 0; const val WIFI = 1; const val CELLULAR = 2; const val ETHERNET = 3; const val VPN = 4; const val OTHER = 5 }

data class EngineConfig(
    val timeoutMs: Int = 1500,
    val dnsSamples: Int = 5,
    val tcpSamples: Int = 3,
    val maxParallel: Int = 4,
    val cooldownMs: Int = 60_000,
    val hysteresisPct: Int = 10,
    val quic: Boolean = true,
    val mtu: Boolean = true,
    val budgetMs: Int = 20_000,
) {
    fun toRecord(): Record = Record()
        .int(Tags.Config.TIMEOUT_MS, timeoutMs).int(Tags.Config.DNS_SAMPLES, dnsSamples)
        .int(Tags.Config.TCP_SAMPLES, tcpSamples).int(Tags.Config.MAX_PARALLEL, maxParallel)
        .int(Tags.Config.COOLDOWN_MS, cooldownMs).int(Tags.Config.HYSTERESIS_PCT, hysteresisPct)
        .int(Tags.Config.QUIC, if (quic) 1 else 0).int(Tags.Config.MTU, if (mtu) 1 else 0)
        .int(Tags.Config.BUDGET_MS, budgetMs)
}

data class EnvironmentInfo(
    val osName: String = "",
    val osVersion: String = "",
    val osBuild: Long = 0,
    val arch: String = "",
    val networkType: Int = NetworkType.UNKNOWN,
    val interfaceName: String = "",
    val dnsServers: List<String> = emptyList(),
    val gateways: List<String> = emptyList(),
    val mtu: Int = 0,
    val hasIpv4: Int = UNKNOWN,
    val hasIpv6: Int = UNKNOWN,
    val captive: Int = UNKNOWN,
    val metered: Int = UNKNOWN,
    val validated: Int = UNKNOWN,
    val privateDns: Int = UNKNOWN,
    val privateDnsName: String = "",
    val connected: Int = UNKNOWN,
    val restrictBackground: Int = UNKNOWN,
) {
    fun toRecord(): Record {
        val r = Record()
            .text(Tags.Env.OS_NAME, osName).text(Tags.Env.OS_VERSION, osVersion).int(Tags.Env.OS_BUILD, osBuild)
            .text(Tags.Env.ARCH, arch).int(Tags.Env.NETWORK_TYPE, networkType).text(Tags.Env.INTERFACE, interfaceName)
            .int(Tags.Env.MTU, mtu).int(Tags.Env.HAS_IPV4, hasIpv4).int(Tags.Env.HAS_IPV6, hasIpv6)
            .int(Tags.Env.CAPTIVE, captive).int(Tags.Env.METERED, metered).int(Tags.Env.VALIDATED, validated)
            .int(Tags.Env.PRIVATE_DNS, privateDns).text(Tags.Env.PRIVATE_DNS_NAME, privateDnsName)
            .int(Tags.Env.CONNECTED, connected).int(Tags.Env.RESTRICT_BACKGROUND, restrictBackground)
        dnsServers.take(8).forEach { r.text(Tags.Env.DNS_SERVER, it) }
        gateways.take(8).forEach { r.text(Tags.Env.GATEWAY, it) }
        return r
    }

    /** Stable fingerprint used to detect network changes without storing history. */
    fun fingerprint(): String = listOf(networkType, interfaceName, dnsServers, gateways, connected, hasIpv6).joinToString("|")

    companion object {
        fun fromRecord(r: Record) = EnvironmentInfo(
            osName = r.getText(Tags.Env.OS_NAME) ?: "",
            osVersion = r.getText(Tags.Env.OS_VERSION) ?: "",
            osBuild = r.getInt(Tags.Env.OS_BUILD) ?: 0,
            arch = r.getText(Tags.Env.ARCH) ?: "",
            networkType = (r.getInt(Tags.Env.NETWORK_TYPE) ?: 0).toInt(),
            interfaceName = r.getText(Tags.Env.INTERFACE) ?: "",
            dnsServers = r.texts(Tags.Env.DNS_SERVER),
            gateways = r.texts(Tags.Env.GATEWAY),
            mtu = (r.getInt(Tags.Env.MTU) ?: 0).toInt(),
            hasIpv4 = (r.getInt(Tags.Env.HAS_IPV4) ?: 2).toInt(),
            hasIpv6 = (r.getInt(Tags.Env.HAS_IPV6) ?: 2).toInt(),
            captive = (r.getInt(Tags.Env.CAPTIVE) ?: 2).toInt(),
            metered = (r.getInt(Tags.Env.METERED) ?: 2).toInt(),
            validated = (r.getInt(Tags.Env.VALIDATED) ?: 2).toInt(),
            privateDns = (r.getInt(Tags.Env.PRIVATE_DNS) ?: 2).toInt(),
            privateDnsName = r.getText(Tags.Env.PRIVATE_DNS_NAME) ?: "",
            connected = (r.getInt(Tags.Env.CONNECTED) ?: 2).toInt(),
            restrictBackground = (r.getInt(Tags.Env.RESTRICT_BACKGROUND) ?: 2).toInt(),
        )
    }
}

data class ResolverResult(
    val server: String, val alternate: Boolean, val sent: Int, val received: Int,
    val avgUs: Long, val jitterUs: Long, val status: Int, val tcpStatus: Int,
)

data class TargetResult(
    val host: String, val port: Int, val literal: Boolean,
    val dnsStatus: Int, val dnsUs: Long, val dnsServer: String, val dnsViaTcp: Boolean, val addresses: List<String>,
    val httpsRecord: Boolean, val alpn: List<String>, val ech: Boolean,
    val tcp4Status: Int, val tcp4Us: Long, val tcp4Attempts: Int, val tcp4Ok: Int,
    val tcp6Status: Int, val tcp6Us: Long, val tcp6Attempts: Int, val tcp6Ok: Int,
    val quicStatus: Int, val quicUs: Long, val quicVersions: List<Long>,
    val mtuStatus: Int, val pathMtu: Int, val mtuCeiling: Int, val mtuProbes: Int,
    val tlsStatus: Int, val tlsUs: Long, val tlsVersion: String, val tlsAlpn: String, val tlsCipher: String,
) {
    val tcpOk: Boolean get() = tcp4Ok > 0 || tcp6Ok > 0
}

data class RunResult(
    val status: Int, val generation: Long, val durationUs: Long,
    val resolvers: List<ResolverResult>, val targets: List<TargetResult>, val invalid: String?,
)

data class Observation(val code: Int, val subject: String, val args: List<Long>)
data class Diagnosis(val category: Int, val confidence: Int, val observations: List<Observation>)
data class Decision(val state: Int, val action: Int, val confidence: Int, val category: Int, val cooldownMs: Long, val param: Long, val highImpact: Boolean)

object DesyncMode {
    const val OFF = 0
    const val SPLIT = 1
    const val DISORDER = 2
    const val FAKE_BAD_SUM = 3
    const val FAKE_AUTO_TTL = 4
    const val QUIC_SCRAMBLE = 5
    const val ADAPTIVE_FULL = 6
    const val REALITY_VISION = 7
}

data class DesyncConfig(
    val mode: Int = DesyncMode.REALITY_VISION,
    val fakeTtl: Int = 5,
    val splitPos: Int = 2,
    val dropRst: Boolean = true,
    val port: Int = 0,
    val persona: String = "",
    val blockTrackers: Boolean = true,
    val stripUrlParams: Boolean = true,
) {
    fun toRecord(): Record = Record()
        .int(Tags.Desync.MODE, mode).int(Tags.Desync.FAKE_TTL, fakeTtl)
        .int(Tags.Desync.SPLIT_POS, splitPos).int(Tags.Desync.DROP_RST, if (dropRst) 1 else 0)
        .int(Tags.Desync.PORT, port)
        .apply { if (persona.isNotEmpty()) text(Tags.Desync.PERSONA, persona) }
        .int(Tags.Desync.BLOCK_TRACKERS, if (blockTrackers) 1 else 0)
        .int(Tags.Desync.STRIP_PARAMS, if (stripUrlParams) 1 else 0)
}

data class DesyncResult(
    val status: Int, val mode: Int, val dropped: Boolean, val protocol: Int,
    val sni: String, val ech: Boolean, val postQuantum: Boolean, val packets: List<ByteArray>,
)

data class ProxyStatus(
    val status: Int, val active: Boolean, val port: Int, val mode: Int,
    val connections: Long = 0, val tlsSplit: Long = 0, val httpSplit: Long = 0,
    val fakeSent: Long = 0, val rstDropped: Long = 0, val visionSplice: Long = 0,
    val trackersBlocked: Long = 0, val paramsStripped: Long = 0,
)

object ServerStatus {
    const val STANDBY = 0
    const val CONNECTED = 1
    const val FAILOVER = 2
    const val UNREACHABLE = 3
    const val REVOKED = 4
    const val QUOTA_EXCEEDED = 5
}

/**
 * User-owned personal server profile ("Your Network. Your Server. Your Control."):
 * - Per-device identity (`deviceId`) and authentication key (`authKeyHex`)
 * - Primary & backup endpoints (`primaryEndpoint`, `backupEndpoint`) with automatic failover
 * - Cover TLS destination (`coverDest`) for REALITY + X25519MLKEM768 active-probing defense
 * - Bandwidth quota tracking (`quotaBytes` / `usedBytes`), latency & packet-loss metrics,
 *   key rotation, and instant device revocation.
 */
data class ServerProfile(
    val id: String,
    val name: String,
    val primaryEndpoint: String,
    val backupEndpoint: String = "",
    val coverDest: String = "dl.google.com",
    val deviceId: String,
    val authKeyHex: String,
    val status: Int = ServerStatus.STANDBY,
    val latencyMs: Long = 0,
    val lossPct: Int = 0,
    val quotaBytes: Long = 0,
    val usedBytes: Long = 0,
    val revoked: Boolean = false,
) {
    val activeEndpoint: String
        get() = if (status == ServerStatus.FAILOVER && backupEndpoint.isNotBlank()) backupEndpoint else primaryEndpoint

    val quotaAvailable: Boolean
        get() = !revoked && (quotaBytes <= 0L || usedBytes < quotaBytes)
}

/**
 * Manages multiple user-owned personal server profiles, per-device key rotation,
 * instant device revocation, quota tracking, and automatic primary -> backup failover.
 */
class ServerManager {
    private val profiles = LinkedHashMap<String, ServerProfile>()
    @Volatile var activeProfileId: String? = null
        private set

    @Synchronized
    fun upsert(profile: ServerProfile) {
        profiles[profile.id] = profile
        if (activeProfileId == null) activeProfileId = profile.id
    }

    @Synchronized
    fun list(): List<ServerProfile> = profiles.values.toList()

    @Synchronized
    fun active(): ServerProfile? = activeProfileId?.let { profiles[it] }

    @Synchronized
    fun select(id: String): ServerProfile? {
        val p = profiles[id] ?: return null
        if (!p.quotaAvailable) return null
        activeProfileId = id
        val updated = p.copy(status = ServerStatus.CONNECTED)
        profiles[id] = updated
        return updated
    }

    @Synchronized
    fun recordTraffic(id: String, bytes: Long): ServerProfile? {
        val p = profiles[id] ?: return null
        val used = (p.usedBytes + bytes).coerceAtLeast(0L)
        val st = if (p.quotaBytes > 0L && used >= p.quotaBytes) ServerStatus.QUOTA_EXCEEDED else p.status
        val updated = p.copy(usedBytes = used, status = st)
        profiles[id] = updated
        return updated
    }

    @Synchronized
    fun revokeDevice(id: String): ServerProfile? {
        val p = profiles[id] ?: return null
        val updated = p.copy(revoked = true, status = ServerStatus.REVOKED)
        profiles[id] = updated
        if (activeProfileId == id) {
            activeProfileId = profiles.values.firstOrNull { it.id != id && it.quotaAvailable }?.id
        }
        return updated
    }

    @Synchronized
    fun rotateDeviceKey(id: String, newKeyHex: String): ServerProfile? {
        if (newKeyHex.isBlank()) return null
        val p = profiles[id] ?: return null
        val updated = p.copy(
            authKeyHex = newKeyHex,
            revoked = false,
            status = if (p.status == ServerStatus.REVOKED) ServerStatus.STANDBY else p.status,
        )
        profiles[id] = updated
        return updated
    }

    @Synchronized
    fun triggerFailover(id: String): ServerProfile? {
        val p = profiles[id] ?: return null
        if (p.backupEndpoint.isNotBlank() && p.quotaAvailable) {
            val updated = p.copy(status = ServerStatus.FAILOVER)
            profiles[id] = updated
            return updated
        }
        val marked = p.copy(status = ServerStatus.UNREACHABLE)
        profiles[id] = marked
        val next = profiles.values.firstOrNull { it.id != id && it.quotaAvailable }
        if (next != null) {
            activeProfileId = next.id
            val promoted = next.copy(status = ServerStatus.CONNECTED)
            profiles[next.id] = promoted
            return promoted
        }
        return marked
    }
}

data class Evaluation(
    val status: Int, val score: Long, val ewma: Long, val generation: Long, val stability: Long,
    val evaluations: Long, val diagnoses: List<Diagnosis>, val decision: Decision?,
    val desyncMode: Int = DesyncMode.OFF,
)

object TlsStatus { const val NOT_RUN = 0; const val OK = 1; const val CERTIFICATE = 2; const val HANDSHAKE = 3; const val TIMEOUT = 4; const val IO = 5; const val UNSUPPORTED = 6 }

data class TlsResult(val host: String, val port: Int, val status: Int, val handshakeUs: Long, val version: String, val alpn: String, val cipher: String) {
    fun toRecord(): Record = Record()
        .text(Tags.Tls.HOST, host).int(Tags.Tls.PORT, port).int(Tags.Tls.STATUS, status)
        .int(Tags.Tls.HANDSHAKE_US, handshakeUs).text(Tags.Tls.VERSION, version)
        .text(Tags.Tls.ALPN, alpn).text(Tags.Tls.CIPHER, cipher)
}

object Decode {
    private fun Record.i(tag: Int) = (getInt(tag) ?: 0L).toInt()
    private fun Record.l(tag: Int) = getInt(tag) ?: 0L

    fun run(bytes: ByteArray?): RunResult {
        val r = Wire.decode(bytes ?: throw WireException("null result"))
        return RunResult(
            status = (r.status ?: Codes.INTERNAL.toLong()).toInt(),
            generation = r.l(Tags.Run.GENERATION),
            durationUs = r.l(Tags.Run.DURATION_US),
            resolvers = r.records(Tags.Run.RESOLVER).map {
                ResolverResult(
                    it.getText(Tags.Resolver.SERVER) ?: "", it.l(Tags.Resolver.ALTERNATE) == 1L,
                    it.i(Tags.Resolver.SENT), it.i(Tags.Resolver.RECEIVED), it.l(Tags.Resolver.AVG_US),
                    it.l(Tags.Resolver.JITTER_US), it.i(Tags.Resolver.STATUS), it.i(Tags.Resolver.TCP_STATUS),
                )
            },
            targets = r.records(Tags.Run.TARGET).map { t ->
                TargetResult(
                    host = t.getText(Tags.Target.HOST) ?: "", port = t.i(Tags.Target.PORT), literal = t.l(Tags.Target.LITERAL) == 1L,
                    dnsStatus = t.i(Tags.Target.DNS_STATUS), dnsUs = t.l(Tags.Target.DNS_US), dnsServer = t.getText(Tags.Target.DNS_SERVER) ?: "",
                    dnsViaTcp = t.l(Tags.Target.DNS_TCP) == 1L, addresses = t.texts(Tags.Target.ADDRESS),
                    httpsRecord = t.l(Tags.Target.HTTPS_RR) == 1L, alpn = t.texts(Tags.Target.ALPN), ech = t.l(Tags.Target.ECH) == 1L,
                    tcp4Status = t.i(Tags.Target.TCP4_STATUS), tcp4Us = t.l(Tags.Target.TCP4_US), tcp4Attempts = t.i(Tags.Target.TCP4_ATTEMPTS), tcp4Ok = t.i(Tags.Target.TCP4_OK),
                    tcp6Status = t.i(Tags.Target.TCP6_STATUS), tcp6Us = t.l(Tags.Target.TCP6_US), tcp6Attempts = t.i(Tags.Target.TCP6_ATTEMPTS), tcp6Ok = t.i(Tags.Target.TCP6_OK),
                    quicStatus = t.i(Tags.Target.QUIC_STATUS), quicUs = t.l(Tags.Target.QUIC_US), quicVersions = t.ints(Tags.Target.QUIC_VERSION),
                    mtuStatus = t.i(Tags.Target.MTU_STATUS), pathMtu = t.i(Tags.Target.PMTU), mtuCeiling = t.i(Tags.Target.MTU_CEILING), mtuProbes = t.i(Tags.Target.MTU_PROBES),
                    tlsStatus = t.i(Tags.Target.TLS_STATUS), tlsUs = t.l(Tags.Target.TLS_US), tlsVersion = t.getText(Tags.Target.TLS_VERSION) ?: "",
                    tlsAlpn = t.getText(Tags.Target.TLS_ALPN) ?: "", tlsCipher = t.getText(Tags.Target.TLS_CIPHER) ?: "",
                )
            },
            invalid = r.getText(Tags.Run.INVALID),
        )
    }

    fun evaluation(bytes: ByteArray?): Evaluation {
        val r = Wire.decode(bytes ?: throw WireException("null result"))
        return Evaluation(
            status = (r.status ?: Codes.INTERNAL.toLong()).toInt(),
            score = r.getInt(Tags.Eval.SCORE) ?: -1, ewma = r.getInt(Tags.Eval.EWMA) ?: -1,
            generation = r.l(Tags.Eval.GENERATION), stability = r.l(Tags.Eval.STABILITY), evaluations = r.l(Tags.Eval.EVALUATIONS),
            diagnoses = r.records(Tags.Eval.DIAGNOSIS).map { d ->
                Diagnosis(
                    d.i(Tags.Diagnosis.CATEGORY), d.i(Tags.Diagnosis.CONFIDENCE),
                    d.records(Tags.Diagnosis.OBSERVATION).map { o -> Observation(o.i(Tags.Observation.CODE), o.getText(Tags.Observation.SUBJECT) ?: "", o.ints(Tags.Observation.ARG)) },
                )
            },
            decision = r.records(Tags.Eval.DECISION).firstOrNull()?.let { d ->
                Decision(
                    d.i(Tags.Decision.STATE), d.i(Tags.Decision.ACTION), d.i(Tags.Decision.CONFIDENCE), d.i(Tags.Decision.CATEGORY),
                    d.l(Tags.Decision.COOLDOWN_MS), d.l(Tags.Decision.PARAM), d.l(Tags.Decision.HIGH_IMPACT) == 1L,
                )
            },
            desyncMode = r.i(Tags.Eval.DESYNC_MODE),
        )
    }

    fun desync(bytes: ByteArray?): DesyncResult {
        val r = Wire.decode(bytes ?: throw WireException("null result"))
        val pkts = r.fields.filter { it.first == Tags.Desync.OUT_PACKET }.mapNotNull { (it.second as? Record.BytesValue)?.v }
        return DesyncResult(
            status = (r.status ?: Codes.INTERNAL.toLong()).toInt(),
            mode = r.i(Tags.Desync.MODE),
            dropped = r.l(Tags.Desync.DROPPED) == 1L,
            protocol = r.i(Tags.Desync.PROTOCOL),
            sni = r.getText(Tags.Desync.SNI) ?: "",
            ech = r.l(Tags.Desync.ECH) == 1L,
            postQuantum = r.l(Tags.Desync.POST_QUANTUM) == 1L,
            packets = pkts,
        )
    }

    fun proxy(bytes: ByteArray?): ProxyStatus {
        val r = Wire.decode(bytes ?: throw WireException("null result"))
        return ProxyStatus(
            status = (r.status ?: Codes.INTERNAL.toLong()).toInt(),
            active = r.l(Tags.Desync.ACTIVE) == 1L,
            port = r.i(Tags.Desync.PORT),
            mode = r.i(Tags.Desync.MODE),
            connections = r.l(Tags.Desync.CONNECTIONS),
            tlsSplit = r.l(Tags.Desync.TLS_SPLIT),
            httpSplit = r.l(Tags.Desync.HTTP_SPLIT),
            fakeSent = r.l(Tags.Desync.FAKE_SENT),
            rstDropped = r.l(Tags.Desync.RST_DROPPED),
            visionSplice = r.l(Tags.Desync.VISION_SPLICE),
            trackersBlocked = r.l(Tags.Desync.TRACKERS_BLOCKED),
            paramsStripped = r.l(Tags.Desync.PARAMS_STRIPPED),
        )
    }
}

// ------------------------------------------------------------------ platform TLS

/**
 * TLS observation through the platform's validated TLS stack (Android Conscrypt /
 * JDK JSSE). Certificate validation is never disabled; failures are reported.
 */
class TlsProber(
    private val factory: SSLSocketFactory,
    private val connect: (host: String, port: Int, timeoutMs: Int) -> Socket,
    private val extraHostnameCheck: ((host: String, session: SSLSession) -> Boolean)? = null,
) {
    fun probe(host: String, port: Int, timeoutMs: Int): TlsResult {
        val start = System.nanoTime()
        fun result(status: Int, version: String = "", alpn: String = "", cipher: String = "") =
            TlsResult(host, port, status, (System.nanoTime() - start) / 1000, version, alpn, cipher)
        var raw: Socket? = null
        var ssl: SSLSocket? = null
        try {
            raw = connect(host, port, timeoutMs)
            raw.soTimeout = timeoutMs
            ssl = factory.createSocket(raw, host, port, true) as SSLSocket
            val params = ssl.sslParameters
            params.endpointIdentificationAlgorithm = "HTTPS"
            params.applicationProtocols = arrayOf("h2", "http/1.1")
            val allowed = ssl.supportedProtocols.filter { it == "TLSv1.3" || it == "TLSv1.2" }
            if (allowed.isEmpty()) return result(TlsStatus.UNSUPPORTED)
            params.protocols = allowed.toTypedArray()
            ssl.sslParameters = params
            ssl.startHandshake()
            val session = ssl.session
            if (extraHostnameCheck != null && !extraHostnameCheck.invoke(host, session)) return result(TlsStatus.CERTIFICATE)
            return result(TlsStatus.OK, session.protocol ?: "", ssl.applicationProtocol ?: "", session.cipherSuite ?: "")
        } catch (e: SSLPeerUnverifiedException) {
            return result(TlsStatus.CERTIFICATE)
        } catch (e: SSLHandshakeException) {
            return result(if (isCertificateProblem(e)) TlsStatus.CERTIFICATE else TlsStatus.HANDSHAKE)
        } catch (e: SocketTimeoutException) {
            return result(TlsStatus.TIMEOUT)
        } catch (e: IOException) {
            return result(if (isCertificateProblem(e)) TlsStatus.CERTIFICATE else TlsStatus.IO)
        } catch (e: RuntimeException) {
            return result(TlsStatus.IO)
        } finally {
            try { ssl?.close() ?: raw?.close() } catch (_: IOException) { }
        }
    }

    private fun isCertificateProblem(e: Throwable): Boolean {
        var c: Throwable? = e
        var depth = 0
        while (c != null && depth++ < 8) {
            if (c is CertificateException || c is CertPathValidatorException || c is SSLPeerUnverifiedException) return true
            c = c.cause
        }
        return false
    }
}

// ------------------------------------------------------------------ session

/** Encrypted-DNS protocol identifiers (mirror of probe::ENC_* in Native/Core.rs). */
object EncProtocol {
    const val UNKNOWN = 0
    const val DOH = 1 // DNS over HTTPS, HTTP/2 (RFC 8484)
    const val DOH3 = 2 // DNS over HTTPS, HTTP/3 over QUIC (RFC 8484 + RFC 9114)
    const val DOT = 3 // DNS over TLS (RFC 7858)
    const val DOQ = 4 // DNS over dedicated QUIC (RFC 9250)
}

/** Result of one HTTPS exchange performed by the platform's own TLS/QUIC stack. */
data class DohResponse(val transport: Int, val rttUs: Long, val protocol: Int, val body: ByteArray?)

/**
 * Platform transport for RFC 8484 DoH: POST application/dns-message over the platform's
 * HTTPS client (HTTP/3 where the platform offers it, HTTP/2 otherwise). Certificate
 * validation is the platform's and is never relaxed.
 */
fun interface DohClient {
    fun post(url: String, body: ByteArray, timeoutMs: Int): DohResponse
}

data class EncryptedResult(val endpoint: String, val name: String, val protocol: Int, val transport: Int, val rttUs: Long, val status: Int = 0)

object Doh {
    const val MAX_ENDPOINTS = 4

    /** Only absolute https:// URLs are accepted: DoH is never sent in clear text. */
    fun validEndpoint(url: String): Boolean =
        url.length <= 256 && url.startsWith("https://") && runCatching { java.net.URI(url).host?.isNotEmpty() == true }.getOrDefault(false)

    /** RFC 8484 query bytes built by the native DNS codec (ID 0). */
    fun query(name: String, qtype: Int = 1): ByteArray? {
        val r = Wire.decode(Native.dohQuery(Wire.encode(Record().text(Tags.DohQuery.NAME, name).int(Tags.DohQuery.QTYPE, qtype))) ?: return null)
        return if (r.status?.toInt() == Codes.OK) r.getBytes(Tags.DohQuery.QUERY) else null
    }
}

data class ProcessInfo(
    val pid: Long, val name: String, val established: Int, val synSent: Int, val listen: Int,
    val closeWait: Int, val udp: Int, val remotes: Int, val sample: List<String>,
)

data class SystemSnapshot(
    val status: Int, val total: Int, val established: Int, val listen: Int, val synSent: Int, val timeWait: Int,
    val closeWait: Int, val udp: Int, val exposed: Int, val processes: List<ProcessInfo>, val findings: List<Observation>,
) {
    companion object {
        /** Machine-wide connections per process (Windows user mode; other platforms: UNSUPPORTED). */
        fun capture(): SystemSnapshot {
            val r = Wire.decode(Native.systemConnections() ?: throw WireException("null result"))
            fun i(rec: Record, tag: Int) = (rec.getInt(tag) ?: 0L).toInt()
            return SystemSnapshot(
                status = (r.status ?: Codes.INTERNAL.toLong()).toInt(),
                total = i(r, Tags.Sysnet.TOTAL), established = i(r, Tags.Sysnet.ESTABLISHED), listen = i(r, Tags.Sysnet.LISTEN),
                synSent = i(r, Tags.Sysnet.SYN_SENT), timeWait = i(r, Tags.Sysnet.TIME_WAIT), closeWait = i(r, Tags.Sysnet.CLOSE_WAIT),
                udp = i(r, Tags.Sysnet.UDP), exposed = i(r, Tags.Sysnet.EXPOSED),
                processes = r.records(Tags.Sysnet.PROCESS).map { p ->
                    ProcessInfo(
                        p.getInt(Tags.Process.PID) ?: 0, p.getText(Tags.Process.NAME) ?: "", i(p, Tags.Process.ESTABLISHED),
                        i(p, Tags.Process.SYN_SENT), i(p, Tags.Process.LISTEN), i(p, Tags.Process.CLOSE_WAIT), i(p, Tags.Process.UDP),
                        i(p, Tags.Process.REMOTES), p.texts(Tags.Process.SAMPLE),
                    )
                },
                findings = r.records(Tags.Sysnet.FINDING).map { f ->
                    Observation(i(f, Tags.Finding.CODE), f.getText(Tags.Finding.SUBJECT) ?: "", f.ints(Tags.Finding.ARG))
                },
            )
        }
    }
}

data class Report(val run: RunResult, val evaluation: Evaluation?, val tls: List<TlsResult>, val encrypted: List<EncryptedResult> = emptyList())

/** Owns one native engine handle; all calls are thread-safe and the handle is never reused. */
class DiagnosticSession(val config: EngineConfig = EngineConfig()) : AutoCloseable {
    private val handle: Long
    @Volatile private var closed = false

    init {
        Native.loadError?.let { throw NativeException(Codes.JNI, "Yerel kütüphane yüklenemedi: ${it.message}") }
        val api = Native.apiVersion()
        if (api != Native.EXPECTED_API) throw NativeException(Codes.UNSUPPORTED, "Yerel API sürümü uyumsuz: $api")
        handle = Native.create(Wire.encode(config.toRecord()))
        if (handle <= 0) throw NativeException(handle.toInt(), "Motor oluşturulamadı (${Text.code(handle.toInt())})")
    }

    private fun live(): Long {
        check(!closed) { "session closed" }
        return handle
    }

    fun setEnvironment(env: EnvironmentInfo): Int = Native.setEnvironment(live(), Wire.encode(env.toRecord()))

    fun diagnose(targets: List<String>, alternateDns: List<String>): RunResult {
        val req = Record()
        targets.forEach { req.text(Tags.Request.TARGET, it) }
        alternateDns.forEach { req.text(Tags.Request.ALT_DNS, it) }
        return Decode.run(Native.diagnose(live(), Wire.encode(req)))
    }

    fun submitTls(results: List<TlsResult>): Int {
        val r = Record()
        results.forEach { r.record(Tags.TlsSubmit.RESULT, it.toRecord()) }
        return Native.submitTls(live(), Wire.encode(r))
    }

    fun evaluate(): Evaluation = Decode.evaluation(Native.evaluate(live()))
    fun networkChanged(): Int = Native.networkChanged(live())
    fun markApplied(action: Int): Int = Native.markApplied(live(), action)

    fun desyncPacket(packet: ByteArray, cfg: DesyncConfig = DesyncConfig()): DesyncResult {
        val req = cfg.toRecord().bytes(Tags.Desync.PACKET, packet)
        return Decode.desync(Native.desyncPacket(live(), Wire.encode(req)))
    }

    fun startProxy(cfg: DesyncConfig = DesyncConfig()): ProxyStatus =
        Decode.proxy(Native.startProxy(live(), Wire.encode(cfg.toRecord())))

    fun updateProxyConfig(cfg: DesyncConfig): ProxyStatus? {
        val current = runCatching { proxyStats() }.getOrNull() ?: return null
        if (!current.active || current.port <= 0) return current
        return startProxy(cfg.copy(port = current.port))
    }

    fun stopProxy(): Int = Native.stopProxy(live())

    fun proxyStats(): ProxyStatus = Decode.proxy(Native.proxyStats(live()))

    /** Full pipeline: native probes → platform TLS on reachable targets → evaluation. */
    /** Measures user-authorized encrypted resolvers and submits them for validation. */
    fun measureEncrypted(run: RunResult, endpoints: List<String>, client: DohClient): List<EncryptedResult> {
        val name = run.targets.firstOrNull { !it.literal }?.host ?: return emptyList()
        val query = Doh.query(name) ?: return emptyList()
        val results = ArrayList<EncryptedResult>()
        val submission = Record()
        for (url in endpoints.filter(Doh::validEndpoint).distinct().take(Doh.MAX_ENDPOINTS)) {
            val r = client.post(url, query, config.timeoutMs)
            val rec = Record().text(Tags.Enc.ENDPOINT, url).int(Tags.Enc.PROTOCOL, r.protocol).int(Tags.Enc.TRANSPORT, r.transport)
                .int(Tags.Enc.RTT_US, r.rttUs).text(Tags.Enc.QUERY_NAME, name).int(Tags.Enc.QTYPE, 1)
            r.body?.let { rec.bytes(Tags.Enc.RESPONSE, it) }
            submission.record(Tags.EncSubmit.RESULT, rec)
            results += EncryptedResult(url, name, r.protocol, r.transport, r.rttUs)
        }
        if (results.isNotEmpty()) Native.submitEncrypted(live(), Wire.encode(submission))
        return results
    }

    fun run(targets: List<String>, alternateDns: List<String>, tls: TlsProber?, doh: DohClient? = null, dohEndpoints: List<String> = emptyList()): Report {
        val run = diagnose(targets, alternateDns)
        if (run.status != Codes.OK) return Report(run, null, emptyList())
        val tlsResults = if (tls == null) emptyList() else run.targets.filter { it.tcpOk }.map { tls.probe(it.host, it.port, config.timeoutMs) }
        if (tlsResults.isNotEmpty()) submitTls(tlsResults)
        // The native run record predates the TLS probes; merge them so the report shows one view.
        val merged = run.copy(
            targets = run.targets.map { t ->
                tlsResults.firstOrNull { it.host == t.host && it.port == t.port }?.let {
                    t.copy(tlsStatus = it.status, tlsUs = it.handshakeUs, tlsVersion = it.version, tlsAlpn = it.alpn, tlsCipher = it.cipher)
                } ?: t
            },
        )
        val encrypted = if (doh != null && dohEndpoints.isNotEmpty()) measureEncrypted(run, dohEndpoints, doh) else emptyList()
        val evaluation = evaluate()
        // Status of each encrypted resolver as validated natively (parser verdict), for display.
        return Report(merged, evaluation, tlsResults, encrypted)
    }

    @Synchronized
    override fun close() {
        if (!closed) {
            closed = true
            Native.destroy(handle)
        }
    }
}

// ------------------------------------------------------------------ text (Turkish UI catalogue)

object Text {
    fun code(c: Int): String = when (c) {
        Codes.OK -> "tamam"
        Codes.INVALID_ARGUMENT -> "geçersiz girdi"
        Codes.INVALID_HANDLE -> "geçersiz motor tanıtıcısı"
        Codes.WIRE -> "veri biçimi hatası"
        Codes.BUSY -> "başka bir tanılama sürüyor"
        Codes.LIMIT -> "sınır aşıldı"
        Codes.PANIC -> "yerel motor iç hatası (yakalandı)"
        Codes.NO_ENVIRONMENT -> "ağ ortamı bilgisi yok"
        Codes.NO_DATA -> "veri yok (ağ değişmiş olabilir; tekrar tanılayın)"
        Codes.UNSUPPORTED -> "bu platformda desteklenmiyor"
        Codes.JNI -> "JNI hatası"
        Codes.INTERNAL -> "iç hata"
        else -> "kod $c"
    }

    fun status(s: Int): String = when (s) {
        0 -> "çalışmadı"; 1 -> "başarılı"; 2 -> "zaman aşımı"; 3 -> "reddedildi"; 4 -> "erişilemez"
        5 -> "hata"; 6 -> "geçersiz yanıt"; 7 -> "kayıt yok"; 8 -> "alan adı yok"; 9 -> "sunucu hatası"
        10 -> "desteklenmiyor"; 11 -> "atlandı"; 12 -> "yerel MTU sınırı"; 13 -> "platform izin vermedi"; else -> "durum $s"
    }

    fun tls(s: Int): String = when (s) {
        TlsStatus.NOT_RUN -> "çalışmadı"; TlsStatus.OK -> "başarılı"; TlsStatus.CERTIFICATE -> "sertifika doğrulanamadı"
        TlsStatus.HANDSHAKE -> "el sıkışma başarısız"; TlsStatus.TIMEOUT -> "zaman aşımı"; TlsStatus.IO -> "bağlantı kesildi"
        TlsStatus.UNSUPPORTED -> "desteklenmiyor"; else -> "durum $s"
    }

    fun category(c: Int): String = when (c) {
        0 -> "—"
        1 -> "DNS çözümleme hatası"
        2 -> "DNS zaman aşımı"
        3 -> "IPv4 bağlantı hatası"
        4 -> "IPv6 bağlantı hatası"
        5 -> "TCP bağlantı hatası"
        6 -> "UDP erişilebilirlik sorunu"
        7 -> "TLS anlaşma hatası"
        8 -> "Sertifika doğrulama hatası"
        9 -> "QUIC uyumsuzluğu"
        10 -> "HTTP/3 uyumsuzluğu"
        11 -> "MTU kaynaklı bağlantı sorunu"
        12 -> "Captive portal (ağ giriş sayfası)"
        13 -> "Yerel ağ kesintisi"
        14 -> "Uzak servis hatası"
        15 -> "Yetersiz kanıt"
        16 -> "Sorun tespit edilmedi"
        17 -> "Bilgilendirme"
        else -> "Kategori $c"
    }

    fun state(s: Int): String = when (s) {
        0 -> "Kararlı"
        1 -> "Ön gözlem — tekrar doğrulanması bekleniyor"
        2 -> "Öneri"
        3 -> "Bekleme süresi (gereksiz değişikliği önlemek için)"
        4 -> "Daha fazla kanıt gerekli"
        5 -> "Uygulanan değişiklik doğrulanıyor"
        6 -> "Değişiklik doğrulandı"
        7 -> "Değişiklik iyileştirme sağlamadı"
        else -> "Durum $s"
    }

    fun actionTitle(a: Int): String = when (a) {
        0 -> "Mevcut yapılandırmayı koru"
        1 -> "IPv4'ü tercih et"
        2 -> "IPv6'yı tercih et"
        3 -> "Alternatif (şifreli) DNS kullan"
        4 -> "TCP (HTTP/2) yoluna güven"
        5 -> "MTU değerini düşür"
        6 -> "Ağ giriş sayfasını aç"
        7 -> "Bekle ve tekrar dene"
        8 -> "Daha fazla ölçüm topla"
        9 -> "Saat ve ağ aracını kontrol et"
        10 -> "Servis sağlayıcı / ağ yöneticisiyle iletişime geç"
        11 -> "Son değişikliği geri al"
        12 -> "Yerel bağlantıyı kontrol et"
        13 -> "Hedef adını kontrol et"
        else -> "Eylem $a"
    }

    fun actionDetail(a: Int, param: Long): String = when (a) {
        0 -> "İşlem gerekmiyor."
        1 -> "IPv6 yolu çalışmıyor, IPv4 çalışıyor. Modem/yönlendirici IPv6 ayarlarını kontrol edin; gerekirse ağ bağdaştırıcısında IPv4'ü önceliklendirin (yönetici izni gerekir)."
        2 -> "IPv4 yolu çalışmıyor, IPv6 çalışıyor. Modem/yönlendirici IPv4 (NAT/DHCP) ayarlarını kontrol edin."
        3 -> "Sistem DNS'i sorunlu görünüyor. Güvendiğiniz bir şifreli DNS hizmetini kendiniz seçip ayarlayabilirsiniz (Android: Ayarlar › Ağ › Özel DNS; Windows: Ayarlar › Ağ › DNS sunucusu ataması › Şifreli DNS). Freedom Network sistem DNS'ini sessizce değiştirmez. Gizlilik notu: seçtiğiniz DNS sağlayıcısı sorgularınızı görür."
        4 -> "UDP/443 (QUIC) yolu yanıt vermiyor; uygulamalar normalde HTTP/2 (TCP) ile otomatik devam eder. Sorun yaşarsanız tarayıcıda QUIC/HTTP3'ü kapatabilirsiniz."
        5 -> "Ölçülen yol MTU'su ${param} bayt. Büyük paketler yolda düşüyor olabilir; bağdaştırıcı MTU değerini bu değere düşürmeyi değerlendirin (yönetici izni gerekir)."
        6 -> "Ağ bir giriş sayfası (captive portal) istiyor. Tarayıcıda giriş yapın; ardından tekrar tanılayın."
        7 -> "TLS anlaşması geçici olarak başarısız oldu. Bir süre sonra tekrar deneyin; sorun sürerse ağ yöneticisine bildirin."
        8 -> "Güvenilir bir sonuç için yeterli ölçüm yok. Tanılamayı tekrar çalıştırın veya başka bir test hedefi ekleyin."
        9 -> "Sertifika doğrulanamadı. Cihaz tarih/saatini, araya giren proxy veya güvenlik yazılımını ve captive portal olasılığını kontrol edin. Sertifika doğrulaması asla devre dışı bırakılmaz."
        10 -> "Sorun bu hedefe özgü görünüyor (diğer hedefler çalışıyor). Hizmet sağlayıcısıyla veya ağ yöneticisiyle iletişime geçin."
        11 -> "Uygulanan değişiklik (${actionTitle(param.toInt())}) bağlantıyı iyileştirmedi. Önceki ayara geri dönün."
        12 -> "Wi-Fi/kablo/mobil veri bağlantısını ve modemi kontrol edin."
        13 -> "Alan adı DNS'te bulunamadı (NXDOMAIN) ve diğer adlar çözülüyor: büyük olasılıkla yazım hatası veya kaldırılmış bir ad. DNS ayarlarını değiştirmek bu sorunu çözmez."
        else -> ""
    }

    fun observation(o: Observation): String {
        val s = o.subject
        fun a(i: Int) = o.args.getOrNull(i)?.toString() ?: "?"
        return when (o.code) {
            1 -> "Aktif ağ bağlantısı yok"
            2 -> "Platform captive portal bildirdi"
            3 -> "Platform internet erişimini doğrulamadı ($s)"
            4 -> "DNS sunucusu $s yanıt vermedi (${a(0)} sorgu, ${a(1)} yanıt)"
            5 -> "DNS sunucusu $s: %${a(0)} paket kaybı"
            6 -> "DNS sunucusu $s UDP'de yanıtsız, TCP'de yanıt veriyor"
            7 -> "$s: alan adı bulunamadı (NXDOMAIN) — yazım hatası olabilir"
            8 -> "$s: DNS sunucu hatası (RCODE ${a(0)})"
            9 -> "$s: DNS zaman aşımı"
            10 -> "$s: IPv4 TCP bağlantısı başarısız (${a(0)} deneme)"
            11 -> "$s: IPv6 TCP bağlantısı başarısız (${a(0)} deneme)"
            12 -> "$s: IPv4 TCP başarılı (${a(0)} ms)"
            13 -> "$s: IPv6 TCP başarılı (${a(0)} ms)"
            14 -> "$s: tüm TCP denemeleri başarısız (${a(0)} deneme)"
            15 -> "$s: TLS sertifikası doğrulanamadı"
            16 -> "$s: TLS anlaşması başarısız"
            17 -> "$s: TLS başarılı"
            18 -> "$s: DNS HTTPS kaydı HTTP/3 (h3) ilan ediyor"
            19 -> "$s: QUIC sürüm anlaşması yanıtı alınamadı (UDP)"
            20 -> "$s: QUIC v1 destekleniyor"
            21 -> "$s: sunucu QUIC v1 listelemiyor"
            22 -> "$s: yol MTU ${a(0)} bayt, beklenen ${a(1)} bayt"
            23 -> "$s: ECH yapılandırması DNS'te yayımlanmış"
            24 -> "$s: cihazda genel IPv6 adresi yok (IPv6 denemesi beklenen şekilde başarısız)"
            25 -> "$s: yüksek gecikme (${a(0)} ms)"
            26 -> "Windows 10 (build ${a(0)}): standart Microsoft desteği 14 Ekim 2025'te sona erdi; güvenlik güncellemeleri için Windows 11'e geçiş veya ESU önerilir"
            27 -> "Diğer hedeflere bağlantı başarılı (${a(0)} hedef)"
            28 -> "Test hedefi belirtilmedi"
            29 -> "$s: DNS sunucusu sorguyu reddetti (REFUSED)"
            30 -> "Ölçülü (kotalı) bağlantı"
            31 -> "DNS sunucusu $s: yüksek jitter (${a(0)} ms)"
            32 -> "Kullanıcı tanımlı DNS $s daha iyi ölçüldü (${a(0)} ms; sistem: ${a(1)} ms)"
            33 -> "$s: adres kaydı yok"
            34 -> "$s: sağlıklı (${a(0)} ms)"
            35 -> "Sonuç çıkarmak için yeterli ölçüm yok"
            36 -> "Arka plan veri kısıtlaması (Veri Tasarrufu) etkin"
            37 -> "Özel DNS (DNS over TLS) etkin${if (s.isNotEmpty()) ": $s" else ""}"
            38 -> "Sistem DNS sunucusu bilgisi alınamadı"
            40 -> "Şifreli DNS ${Text.encProtocol(o.args.getOrNull(1)?.toInt() ?: 0)} ($s) yanıtladı (${a(0)} ms)"
            41 -> "Şifreli DNS kullanılabilir: ${Text.encProtocol(o.args.getOrNull(1)?.toInt() ?: 0)} $s ${a(0)} ms (sistem DNS: ${a(2)} ms). Gizlilik için sistemde şifreli DNS'i etkinleştirmeyi değerlendirin"
            42 -> "Şifreli DNS $s yanıt vermedi (${status(o.args.getOrNull(0)?.toInt() ?: 5)}); uç nokta veya ağ politikası olabilir"
            43 -> "$s: sistem DNS'i alan adı yok diyor, bağımsız şifreli DNS (${Text.encProtocol(o.args.getOrNull(0)?.toInt() ?: 0)}) çözüyor — çözümleyici düzeyinde tutarsızlık"
            44 -> "$s: şifreli DNS de alan adının olmadığını doğruluyor"
            45 -> "$s: DNS yanıtı zehirlenmiş / sansür IP'sine yönlendirildi (${a(0)}.${a(1)}.${a(2)}.${a(3)})"
            39 -> "$s: işletim sistemi bağlantıya izin vermedi (Android 17+: yerel ağ adresleri ACCESS_LOCAL_NETWORK izni gerektirir; Freedom Network bu izni istemez). Bu bir ağ arızası değildir."
            else -> "Gözlem ${o.code} $s ${o.args}"
        }
    }

    const val KNOWN_OBSERVATIONS = 45

    fun encProtocol(p: Int): String = when (p) {
        EncProtocol.DOH -> "DoH (HTTP/2)"
        EncProtocol.DOH3 -> "DoH3 (HTTP/3)"
        EncProtocol.DOT -> "DoT"
        EncProtocol.DOQ -> "DoQ"
        else -> "şifreli DNS"
    }
    const val KNOWN_CATEGORIES = 17
    const val KNOWN_ACTIONS = 13

    private fun ms(us: Long) = "${us / 1000} ms"

    fun networkType(t: Int) = when (t) {
        NetworkType.WIFI -> "Wi-Fi"; NetworkType.CELLULAR -> "Mobil veri"; NetworkType.ETHERNET -> "Ethernet"
        NetworkType.VPN -> "VPN/tünel"; NetworkType.OTHER -> "Diğer"; else -> "Bilinmiyor"
    }

    private fun tri(v: Int) = when (v) { YES -> "evet"; NO -> "hayır"; else -> "bilinmiyor" }

    fun systemFinding(o: Observation): String {
        fun a(i: Int) = o.args.getOrNull(i)?.toString() ?: "?"
        return when (o.code) {
            1 -> "${o.subject} (PID ${a(1)}): ${a(0)} bağlantı el sıkışmada takılı (SYN_SENT) — uzak uç erişilemez veya yol filtreleniyor olabilir"
            2 -> "${o.subject} (PID ${a(1)}): ${a(0)} bağlantı kapatılmayı bekliyor (CLOSE_WAIT) — uygulama soketleri kapatmıyor olabilir"
            3 -> "Sistemde ${a(0)} TIME_WAIT bağlantısı: kısa ömürlü bağlantı yoğunluğu, kaynak port tükenmesi riski"
            4 -> "${a(0)} servis tüm arayüzlerde dinliyor (0.0.0.0/::): güvenlik duvarı izin verirse ağdan erişilebilir"
            5 -> "Etkin TCP bağlantısı yok"
            else -> "Bulgu ${o.code} ${o.subject} ${o.args}"
        }
    }

    const val KNOWN_SYSTEM_FINDINGS = 5

    fun system(s: SystemSnapshot): String = buildString {
        if (s.status != Codes.OK) {
            appendLine("Sistem geneli bağlantı görünümü: ${code(s.status)}")
            return@buildString
        }
        appendLine("SİSTEM GENELİ BAĞLANTILAR (yalnızca bu cihazda gösterilir, kaydedilmez)")
        appendLine("  Toplam ${s.total} · kurulu ${s.established} · dinleyen ${s.listen} · el sıkışmada ${s.synSent} · TIME_WAIT ${s.timeWait} · CLOSE_WAIT ${s.closeWait} · UDP ${s.udp}")
        if (s.findings.isNotEmpty()) {
            appendLine()
            appendLine("BULGULAR")
            s.findings.forEach { appendLine("  • ${systemFinding(it)}") }
        }
        appendLine()
        appendLine("İŞLEMLER (en fazla 64)")
        for (p in s.processes) {
            val parts = buildList {
                if (p.established > 0) add("kurulu ${p.established}")
                if (p.synSent > 0) add("el sıkışmada ${p.synSent}")
                if (p.listen > 0) add("dinleyen ${p.listen}")
                if (p.closeWait > 0) add("CLOSE_WAIT ${p.closeWait}")
                if (p.udp > 0) add("UDP ${p.udp}")
                if (p.remotes > 0) add("uzak uç ${p.remotes}")
            }
            appendLine("  ${p.name} (PID ${p.pid}): ${parts.joinToString(", ")}")
            if (p.sample.isNotEmpty()) appendLine("      → ${p.sample.joinToString(", ")}")
        }
    }

    fun environment(e: EnvironmentInfo): String = buildString {
        appendLine("ORTAM")
        appendLine("  Sistem      : ${e.osName} ${e.osVersion}${if (e.osBuild > 0) " (build ${e.osBuild})" else ""} · ${e.arch}")
        appendLine("  Ağ          : ${networkType(e.networkType)} · ${e.interfaceName.ifEmpty { "?" }} · bağlı: ${tri(e.connected)}")
        appendLine("  DNS         : ${e.dnsServers.ifEmpty { listOf("?") }.joinToString(", ")}")
        appendLine("  Ağ geçidi   : ${e.gateways.ifEmpty { listOf("?") }.joinToString(", ")}")
        appendLine("  MTU         : ${if (e.mtu > 0) e.mtu else "?"} · IPv4: ${tri(e.hasIpv4)} · IPv6: ${tri(e.hasIpv6)}")
        appendLine("  Captive     : ${tri(e.captive)} · doğrulanmış: ${tri(e.validated)} · ölçülü: ${tri(e.metered)}")
    }

    fun report(r: Report): String = buildString {
        val run = r.run
        if (run.status != Codes.OK) {
            appendLine("Tanılama yapılamadı: ${code(run.status)}${run.invalid?.let { " — '$it'" } ?: ""}")
            return@buildString
        }
        appendLine("ÖLÇÜMLER (${run.durationUs / 1000} ms)")
        for (s in run.resolvers) {
            appendLine("  DNS ${s.server}${if (s.alternate) " [kullanıcı tanımlı]" else ""}: ${s.received}/${s.sent} yanıt, ort. ${ms(s.avgUs)}, jitter ${ms(s.jitterUs)}${if (s.tcpStatus != 0) ", TCP: ${status(s.tcpStatus)}" else ""}")
        }
        for (t in run.targets) {
            appendLine("  ${t.host}:${t.port}")
            if (!t.literal) appendLine("    DNS   : ${status(t.dnsStatus)} ${ms(t.dnsUs)}${if (t.dnsViaTcp) " (TCP)" else ""} → ${t.addresses.take(4).joinToString(", ").ifEmpty { "—" }}")
            if (t.httpsRecord) appendLine("    HTTPS : ALPN ${t.alpn.joinToString(",")}${if (t.ech) ", ECH yayımlanmış" else ""}")
            if (t.tcp4Attempts > 0) appendLine("    TCP4  : ${status(t.tcp4Status)} ${t.tcp4Ok}/${t.tcp4Attempts}, medyan ${ms(t.tcp4Us)}")
            if (t.tcp6Attempts > 0) appendLine("    TCP6  : ${status(t.tcp6Status)} ${t.tcp6Ok}/${t.tcp6Attempts}, medyan ${ms(t.tcp6Us)}")
            if (t.tlsStatus != 0) appendLine("    TLS   : ${tls(t.tlsStatus)} ${ms(t.tlsUs)} ${t.tlsVersion} ${t.tlsAlpn} ${t.tlsCipher}".trimEnd())
            if (t.quicStatus != 11) appendLine("    QUIC  : ${status(t.quicStatus)}${if (t.quicVersions.isNotEmpty()) " sürümler " + t.quicVersions.joinToString(",") { "0x" + it.toString(16) } else ""}")
            if (t.mtuStatus == 1) appendLine("    MTU   : yol ${t.pathMtu}/${t.mtuCeiling} bayt (${t.mtuProbes} prob)")
        }
        if (r.encrypted.isNotEmpty()) {
            appendLine("  Şifreli DNS (sorgu: ${r.encrypted.first().name})")
            for (x in r.encrypted) {
                appendLine("    ${x.endpoint}: ${encProtocol(x.protocol)}, aktarım ${status(x.transport)}, ${ms(x.rttUs)}")
            }
        }
        val e = r.evaluation ?: return@buildString
        appendLine()
        val stability = if (e.evaluations >= 2) ", kararlılık ${e.stability}/1000" else ""
        appendLine("TEŞHİS (puan ${e.score}/1000, ortalama ${e.ewma}$stability)")
        for (d in e.diagnoses) {
            appendLine("  • ${category(d.category)} — güven %${d.confidence}")
            d.observations.forEach { appendLine("      - ${observation(it)}") }
        }
        e.decision?.let { d ->
            appendLine()
            appendLine("KARAR: ${state(d.state)}")
            appendLine("  ${actionTitle(d.action)}${if (d.highImpact) " (sistem ayarı — yalnızca sizin onayınızla)" else ""}")
            actionDetail(d.action, d.param).takeIf { it.isNotEmpty() }?.let { appendLine("  $it") }
            if ((d.state == 1 || d.state == 3) && d.param > 0) {
                appendLine("  Değerlendirilen öneri: ${actionTitle(d.param.toInt())} (tek ölçümle sistem değişikliği önerilmez)")
            }
            if (d.cooldownMs > 0) appendLine("  Yeni değişiklik önerisi için kalan süre: ${d.cooldownMs / 1000} sn")
        }
        if (e.desyncMode != DesyncMode.OFF) {
            appendLine()
            appendLine("AKTİF DPI AŞMA (DESYNC) ÖNERİSİ: ${desyncMode(e.desyncMode)}")
        }
    }

    const val KNOWN_DESYNC_MODES = 7

    fun desyncMode(m: Int): String = when (m) {
        DesyncMode.OFF -> "Kapalı (Doğrudan Geçiş)"
        DesyncMode.SPLIT -> "TLS SNI/ECH + HTTP Host Bölme (Split)"
        DesyncMode.DISORDER -> "Ters Sıralı TCP Segmentasyonu (Multi-Disorder)"
        DesyncMode.FAKE_BAD_SUM -> "Sahte Paket (RFC 1624 BadSum) + Disorder"
        DesyncMode.FAKE_AUTO_TTL -> "Sahte Paket (Oto-TTL) + Disorder"
        DesyncMode.QUIC_SCRAMBLE -> "QUIC v1/v2 Initial Şaşırtma + TCP/TLS 1.3 Yedeği"
        DesyncMode.ADAPTIVE_FULL -> "Tam Adaptif Özgürlük Modu (PQ-TLS 1.3 + ECH + Oto-TTL + BadSum + RST Kalkanı)"
        DesyncMode.REALITY_VISION -> "REALITY + ML-KEM-768 + xtls-rprx-vision Doğrudan Aktarım (2026–2027)"
        else -> "Mod $m"
    }

    fun serverStatus(s: Int): String = when (s) {
        ServerStatus.STANDBY -> "Beklemede"
        ServerStatus.CONNECTED -> "Bağlı"
        ServerStatus.FAILOVER -> "Yedek Sunucuda (Failover)"
        ServerStatus.UNREACHABLE -> "Erişilemez"
        ServerStatus.REVOKED -> "Cihaz Erişimi İptal Edildi"
        ServerStatus.QUOTA_EXCEEDED -> "Kota Doldu"
        else -> "Durum $s"
    }

    fun serverManager(mgr: ServerManager): String = buildString {
        val list = mgr.list()
        appendLine("FREEDOM NETWORK — KİŞİSEL SUNUCU YÖNETİCİSİ (${list.size} profil)")
        for (p in list) {
            val kota = if (p.quotaBytes > 0) "${p.usedBytes}/${p.quotaBytes} bayt" else "${p.usedBytes} bayt (sınırsız)"
            appendLine("  • ${p.name} [${serverStatus(p.status)}] → ${p.activeEndpoint} (REALITY hedefi: ${p.coverDest} · cihaz: ${p.deviceId} · gecikme: ${p.latencyMs} ms · kayıp: %${p.lossPct} · kota: $kota)")
        }
    }

    fun proxyStatus(p: ProxyStatus): String = buildString {
        if (!p.active) {
            appendLine("FREEDOM NETWORK (YEREL DPI AŞMA): Kapalı")
            return@buildString
        }
        appendLine("FREEDOM NETWORK (YEREL DPI AŞMA): Etkin · 127.0.0.1:${p.port} (SOCKS5 + HTTP CONNECT)")
        appendLine("  Strateji   : ${desyncMode(p.mode)}")
        appendLine("  İstatistik : bağlantı ${p.connections} · TLS bölme ${p.tlsSplit} · HTTP bölme ${p.httpSplit} · sahte paket ${p.fakeSent} · RST kalkanı ${p.rstDropped} · Vision doğrudan aktarım ${p.visionSplice} · izleyici engeli ${p.trackersBlocked} · URL temizleme ${p.paramsStripped}")
    }

    fun vpnStatus(
        vpnActive: Boolean,
        p: ProxyStatus,
        tcpFlows: Int = 0,
        udpFlows: Int = 0,
        dnsQueries: Int = 0,
        dohResolved: Int = 0,
        desyncedFlows: Int = 0,
        visionSplicedFlows: Int = 0,
        poisonedBlocked: Int = 0,
        quicFallbacks: Int = 0,
        tlsFragmented: Int = 0,
        bytesUp: Long = 0,
        bytesDown: Long = 0,
        trackersBlocked: Int = 0,
        leaksBlocked: Int = 0,
        killSwitch: Boolean = false,
        exitRelayLabel: String = "",
        ipMasked: Boolean = false,
        maskMethodLabel: String = "",
        devicePersonaLabel: String = "",
        locationShieldLabel: String = "",
    ): String = buildString {
        if (!vpnActive && !p.active) {
            appendLine("FREEDOM NETWORK (SİSTEM GENELİ ÖZGÜR AĞ): Kapalı")
            return@buildString
        }
        val activeLabel = maskMethodLabel.ifBlank { exitRelayLabel }
        val isMaskedNow = ipMasked || (activeLabel.isNotBlank() && !activeLabel.startsWith("Doğrudan"))
        val modeDesc = if (vpnActive) {
            if (isMaskedNow && activeLabel.isNotBlank()) {
                "Sistem Geneli Gizlilik Tüneli ($activeLabel)"
            } else {
                "Sistem Geneli TUN Köprüsü (DoH3 + REALITY/Vision Desync + Tam UDP NAT)"
            }
        } else {
            "Yerel Proxy (127.0.0.1:${p.port})"
        }
        appendLine("FREEDOM NETWORK: Etkin · $modeDesc")
        if (p.active) {
            appendLine("  Yerel Proxy: 127.0.0.1:${p.port} (SOCKS5 + HTTP CONNECT)")
        }
        if (isMaskedNow && activeLabel.isNotBlank()) {
            appendLine("  Çıkış IP   : MASKELİ · $activeLabel")
        } else if (vpnActive) {
            appendLine("  Çıkış IP   : Doğrudan (Yerel DoH3 + DPI Açık · Tünel/Röle Bağlanmadı)")
        }
        if (locationShieldLabel.isNotBlank()) {
            appendLine("  Konum Kalkanı : $locationShieldLabel")
        }
        if (devicePersonaLabel.isNotBlank()) {
            appendLine("  Cihaz Kimliği : $devicePersonaLabel")
        }
        appendLine("  Strateji   : ${desyncMode(p.mode)}${if (killSwitch) " · Sızdırmaz Kill Switch AKTİF" else ""}")
        appendLine("  TUN Köprüsü: TCP $tcpFlows (Desync $desyncedFlows, TLS Parçalama $tlsFragmented, Vision $visionSplicedFlows) · UDP $udpFlows (QUIC $quicFallbacks) · DNS $dnsQueries (DoH $dohResolved, Zehir $poisonedBlocked, İzleyici $trackersBlocked, Sızıntı $leaksBlocked)")
        if (bytesUp > 0 || bytesDown > 0) {
            appendLine("  Veri Akışı : Yükleme ${bytesUp / 1024} KB · İndirme ${bytesDown / 1024} KB")
        }
        appendLine("  Motor İstat: bağlantı ${p.connections} · TLS bölme ${p.tlsSplit} · HTTP bölme ${p.httpSplit} · sahte paket ${p.fakeSent} · RST kalkanı ${p.rstDropped} · Vision doğrudan aktarım ${p.visionSplice}")
    }

    fun telemetryReport(s: GlobalTelemetrySnapshot): String = buildString {
        appendLine("KÜRESEL GÖNÜLLÜ AĞI & CANLI SANSÜR TELEMETRİSİ (${s.ripe.countryCode})")
        if (s.cloudflare.ok) {
            appendLine("  Cloudflare : IP=${s.cloudflare.ip.ifBlank { "?" }} · WARP=${s.cloudflare.warp} · Bölge=${s.cloudflare.loc}/${s.cloudflare.colo} · SNI=${s.cloudflare.sni} · HTTP=${s.cloudflare.http}")
        } else {
            appendLine("  Cloudflare : erişilemedi (${s.cloudflare.error})")
        }
        if (s.ripe.ok) {
            val asnSample = if (s.ripe.sampleAsnNames.isNotEmpty()) " [örnek ASN: ${s.ripe.sampleAsnNames.joinToString(", ")}]" else ""
            appendLine("  RIPE Atlas : ${s.ripe.connectedCount} aktif donanım probu · ${s.ripe.distinctAsns} farklı ASN (${s.ripe.queryMs} ms)$asnSample")
        } else {
            appendLine("  RIPE Atlas : erişilemedi (${s.ripe.error})")
        }
        if (s.ooniOk) {
            val anom = s.ooni.count { it.anomaly || it.confirmed }
            appendLine("  OONI Ağı   : son ${s.ooni.size} gönüllü ölçümünde $anom sansür/anomali (${s.ooniQueryMs} ms)")
            for (m in s.ooni.take(6)) {
                val tag = when {
                    m.confirmed -> "ENGEL"
                    m.anomaly -> "ANOMALİ"
                    m.failure -> "HATA"
                    else -> "NORMAL"
                }
                val tgt = m.input.ifBlank { m.testName }
                appendLine("    • [$tag] ${m.testName} · ${m.probeAsn.ifBlank { "?" }} · $tgt")
            }
        } else {
            appendLine("  OONI Ağı   : erişilemedi (${s.ooniError})")
        }
        if (s.mlab.ok) {
            appendLine("  M-Lab Düğüm: ${s.mlab.machine} (${s.mlab.city}, ${s.mlab.country} · ${s.mlab.queryMs} ms)")
        } else {
            appendLine("  M-Lab Düğüm: erişilemedi (${s.mlab.error})")
        }
    }
}

// ------------------------------------------------------------------ embedded 24x24 SVG vector icon engine

enum class FreedomIconId {
    SHIELD_CHECK,
    SHIELD_OFF,
    RADAR,
    SLIDERS,
    ACTIVITY,
    TERMINAL,
    GLOBE,
    ZAP,
    SERVER,
    SPLIT,
    WIFI,
    ETHERNET,
    EYE_OFF,
    LINK_2_OFF,
    FINGERPRINT,
    MAP_PIN_OFF,
    LOCK,
    KEY_ROUND,
    PLAY,
    SQUARE,
    REFRESH_CW,
    COPY,
    DOWNLOAD,
    CHECK_CIRCLE,
    ALERT_TRIANGLE,
    INFO,
    EXTERNAL_LINK,
    ARROW_DOWN,
    ARROW_UP,
    CHEVRON_DOWN,
    CHEVRON_UP,
    BUG,
    SPARKLES,
    CPU,
}

sealed interface SvgCmd {
    data class MoveTo(val x: Float, val y: Float) : SvgCmd
    data class LineTo(val x: Float, val y: Float) : SvgCmd
    data class QuadTo(val cx: Float, val cy: Float, val x: Float, val y: Float) : SvgCmd
    data class CubicTo(val c1x: Float, val c1y: Float, val c2x: Float, val c2y: Float, val x: Float, val y: Float) : SvgCmd
    data object Close : SvgCmd
}

/** Zero-dependency 24x24 SVG path parser supporting M/m, L/l, H/h, V/v, C/c, S/s, Q/q, T/t, A/a, Z/z. */
object SvgPathParser {
    private class Cursor(val s: String) {
        var i = 0
        fun skipSep() {
            while (i < s.length && (s[i].isWhitespace() || s[i] == ',')) i++
        }
        fun hasNextNumber(): Boolean {
            skipSep()
            if (i >= s.length) return false
            val c = s[i]
            return c == '-' || c == '+' || c == '.' || c in '0'..'9'
        }
        fun nextFloat(): Float {
            skipSep()
            val start = i
            if (i < s.length && (s[i] == '-' || s[i] == '+')) i++
            while (i < s.length && s[i] in '0'..'9') i++
            if (i < s.length && s[i] == '.') {
                i++
                while (i < s.length && s[i] in '0'..'9') i++
            }
            if (i < s.length && (s[i] == 'e' || s[i] == 'E')) {
                i++
                if (i < s.length && (s[i] == '-' || s[i] == '+')) i++
                while (i < s.length && s[i] in '0'..'9') i++
            }
            if (i == start) return 0f
            return s.substring(start, i).toFloatOrNull() ?: 0f
        }
        fun nextFlag(): Boolean {
            skipSep()
            if (i >= s.length) return false
            val c = s[i++]
            return c != '0'
        }
    }

    private fun arcToCubic(
        out: MutableList<SvgCmd>,
        x0: Double,
        y0: Double,
        rxIn: Double,
        ryIn: Double,
        angleDeg: Double,
        largeArc: Boolean,
        sweep: Boolean,
        x: Double,
        y: Double,
    ) {
        if (kotlin.math.abs(x0 - x) < 1e-6 && kotlin.math.abs(y0 - y) < 1e-6) return
        var rx = kotlin.math.abs(rxIn)
        var ry = kotlin.math.abs(ryIn)
        if (rx < 1e-6 || ry < 1e-6) {
            out.add(SvgCmd.LineTo(x.toFloat(), y.toFloat()))
            return
        }
        val phi = Math.toRadians(angleDeg)
        val cosPhi = kotlin.math.cos(phi)
        val sinPhi = kotlin.math.sin(phi)
        val dx2 = (x0 - x) / 2.0
        val dy2 = (y0 - y) / 2.0
        val x1p = cosPhi * dx2 + sinPhi * dy2
        val y1p = -sinPhi * dx2 + cosPhi * dy2

        val lambda = (x1p * x1p) / (rx * rx) + (y1p * y1p) / (ry * ry)
        if (lambda > 1.0) {
            val s = kotlin.math.sqrt(lambda)
            rx *= s
            ry *= s
        }
        val rx2 = rx * rx
        val ry2 = ry * ry
        val x1p2 = x1p * x1p
        val y1p2 = y1p * y1p
        val num = kotlin.math.max(0.0, rx2 * ry2 - rx2 * y1p2 - ry2 * x1p2)
        val den = rx2 * y1p2 + ry2 * x1p2
        val factor = if (den < 1e-12) 0.0 else kotlin.math.sqrt(num / den) * if (largeArc == sweep) -1.0 else 1.0
        val cxp = factor * ((rx * y1p) / ry)
        val cyp = factor * (-(ry * x1p) / rx)
        val cx = cosPhi * cxp - sinPhi * cyp + (x0 + x) / 2.0
        val cy = sinPhi * cxp + cosPhi * cyp + (y0 + y) / 2.0

        fun vecAngle(ux: Double, uy: Double, vx: Double, vy: Double): Double {
            val dot = ux * vx + uy * vy
            val mag = kotlin.math.sqrt((ux * ux + uy * uy) * (vx * vx + vy * vy)).coerceAtLeast(1e-12)
            val cosVal = (dot / mag).coerceIn(-1.0, 1.0)
            val ang = kotlin.math.acos(cosVal)
            return if (ux * vy - uy * vx < 0.0) -ang else ang
        }

        val vx0 = (x1p - cxp) / rx
        val vy0 = (y1p - cyp) / ry
        val vx1 = (-x1p - cxp) / rx
        val vy1 = (-y1p - cyp) / ry
        val theta1 = vecAngle(1.0, 0.0, vx0, vy0)
        var dTheta = vecAngle(vx0, vy0, vx1, vy1)
        if (!sweep && dTheta > 0.0) dTheta -= 2.0 * Math.PI
        if (sweep && dTheta < 0.0) dTheta += 2.0 * Math.PI

        val segs = kotlin.math.max(1, kotlin.math.ceil(kotlin.math.abs(dTheta) / (Math.PI / 2.0)).toInt())
        val delta = dTheta / segs
        val t = (4.0 / 3.0) * kotlin.math.tan(delta / 4.0)
        for (k in 0 until segs) {
            val a1 = theta1 + k * delta
            val a2 = a1 + delta
            val cos1 = kotlin.math.cos(a1)
            val sin1 = kotlin.math.sin(a1)
            val cos2 = kotlin.math.cos(a2)
            val sin2 = kotlin.math.sin(a2)
            val ep1x = cos1 - sin1 * t
            val ep1y = sin1 + cos1 * t
            val ep2x = cos2 + sin2 * t
            val ep2y = sin2 - cos2 * t
            val c1x = cx + cosPhi * (rx * ep1x) - sinPhi * (ry * ep1y)
            val c1y = cy + sinPhi * (rx * ep1x) + cosPhi * (ry * ep1y)
            val c2x = cx + cosPhi * (rx * ep2x) - sinPhi * (ry * ep2y)
            val c2y = cy + sinPhi * (rx * ep2x) + cosPhi * (ry * ep2y)
            val ex = cx + cosPhi * (rx * cos2) - sinPhi * (ry * sin2)
            val ey = cy + sinPhi * (rx * cos2) + cosPhi * (ry * sin2)
            out.add(SvgCmd.CubicTo(c1x.toFloat(), c1y.toFloat(), c2x.toFloat(), c2y.toFloat(), ex.toFloat(), ey.toFloat()))
        }
    }

    fun parse(d: String): List<SvgCmd> {
        val out = ArrayList<SvgCmd>(32)
        val cur = Cursor(d)
        var cx = 0f
        var cy = 0f
        var sx = 0f
        var sy = 0f
        var lastCtrlX = 0f
        var lastCtrlY = 0f
        var lastCmd = ' '

        while (true) {
            cur.skipSep()
            if (cur.i >= cur.s.length) break
            var cmd = cur.s[cur.i]
            if (cmd.isLetter()) {
                cur.i++
            } else {
                cmd = when (lastCmd) {
                    'M' -> 'L'
                    'm' -> 'l'
                    else -> lastCmd
                }
            }
            when (cmd) {
                'M', 'm' -> {
                    var first = true
                    while (cur.hasNextNumber()) {
                        val nx = cur.nextFloat() + if (cmd == 'm') cx else 0f
                        val ny = cur.nextFloat() + if (cmd == 'm') cy else 0f
                        if (first) {
                            out.add(SvgCmd.MoveTo(nx, ny))
                            sx = nx; sy = ny
                            first = false
                        } else {
                            out.add(SvgCmd.LineTo(nx, ny))
                        }
                        cx = nx; cy = ny
                    }
                    lastCtrlX = cx; lastCtrlY = cy
                }
                'L', 'l' -> {
                    while (cur.hasNextNumber()) {
                        val nx = cur.nextFloat() + if (cmd == 'l') cx else 0f
                        val ny = cur.nextFloat() + if (cmd == 'l') cy else 0f
                        out.add(SvgCmd.LineTo(nx, ny))
                        cx = nx; cy = ny
                    }
                    lastCtrlX = cx; lastCtrlY = cy
                }
                'H', 'h' -> {
                    while (cur.hasNextNumber()) {
                        val nx = cur.nextFloat() + if (cmd == 'h') cx else 0f
                        out.add(SvgCmd.LineTo(nx, cy))
                        cx = nx
                    }
                    lastCtrlX = cx; lastCtrlY = cy
                }
                'V', 'v' -> {
                    while (cur.hasNextNumber()) {
                        val ny = cur.nextFloat() + if (cmd == 'v') cy else 0f
                        out.add(SvgCmd.LineTo(cx, ny))
                        cy = ny
                    }
                    lastCtrlX = cx; lastCtrlY = cy
                }
                'C', 'c' -> {
                    while (cur.hasNextNumber()) {
                        val rel = cmd == 'c'
                        val c1x = cur.nextFloat() + if (rel) cx else 0f
                        val c1y = cur.nextFloat() + if (rel) cy else 0f
                        val c2x = cur.nextFloat() + if (rel) cx else 0f
                        val c2y = cur.nextFloat() + if (rel) cy else 0f
                        val nx = cur.nextFloat() + if (rel) cx else 0f
                        val ny = cur.nextFloat() + if (rel) cy else 0f
                        out.add(SvgCmd.CubicTo(c1x, c1y, c2x, c2y, nx, ny))
                        lastCtrlX = c2x; lastCtrlY = c2y
                        cx = nx; cy = ny
                    }
                }
                'S', 's' -> {
                    while (cur.hasNextNumber()) {
                        val rel = cmd == 's'
                        val c1x = if (lastCmd in "CcSs") 2f * cx - lastCtrlX else cx
                        val c1y = if (lastCmd in "CcSs") 2f * cy - lastCtrlY else cy
                        val c2x = cur.nextFloat() + if (rel) cx else 0f
                        val c2y = cur.nextFloat() + if (rel) cy else 0f
                        val nx = cur.nextFloat() + if (rel) cx else 0f
                        val ny = cur.nextFloat() + if (rel) cy else 0f
                        out.add(SvgCmd.CubicTo(c1x, c1y, c2x, c2y, nx, ny))
                        lastCtrlX = c2x; lastCtrlY = c2y
                        cx = nx; cy = ny
                        lastCmd = cmd
                    }
                }
                'Q', 'q' -> {
                    while (cur.hasNextNumber()) {
                        val rel = cmd == 'q'
                        val c1x = cur.nextFloat() + if (rel) cx else 0f
                        val c1y = cur.nextFloat() + if (rel) cy else 0f
                        val nx = cur.nextFloat() + if (rel) cx else 0f
                        val ny = cur.nextFloat() + if (rel) cy else 0f
                        out.add(SvgCmd.QuadTo(c1x, c1y, nx, ny))
                        lastCtrlX = c1x; lastCtrlY = c1y
                        cx = nx; cy = ny
                    }
                }
                'T', 't' -> {
                    while (cur.hasNextNumber()) {
                        val rel = cmd == 't'
                        val c1x = if (lastCmd in "QqTt") 2f * cx - lastCtrlX else cx
                        val c1y = if (lastCmd in "QqTt") 2f * cy - lastCtrlY else cy
                        val nx = cur.nextFloat() + if (rel) cx else 0f
                        val ny = cur.nextFloat() + if (rel) cy else 0f
                        out.add(SvgCmd.QuadTo(c1x, c1y, nx, ny))
                        lastCtrlX = c1x; lastCtrlY = c1y
                        cx = nx; cy = ny
                        lastCmd = cmd
                    }
                }
                'A', 'a' -> {
                    while (cur.hasNextNumber()) {
                        val rel = cmd == 'a'
                        val rx = cur.nextFloat().toDouble()
                        val ry = cur.nextFloat().toDouble()
                        val rot = cur.nextFloat().toDouble()
                        val large = cur.nextFlag()
                        val sweep = cur.nextFlag()
                        val nx = cur.nextFloat() + if (rel) cx else 0f
                        val ny = cur.nextFloat() + if (rel) cy else 0f
                        arcToCubic(out, cx.toDouble(), cy.toDouble(), rx, ry, rot, large, sweep, nx.toDouble(), ny.toDouble())
                        cx = nx; cy = ny
                        lastCtrlX = cx; lastCtrlY = cy
                    }
                }
                'Z', 'z' -> {
                    out.add(SvgCmd.Close)
                    cx = sx; cy = sy
                    lastCtrlX = cx; lastCtrlY = cy
                }
                else -> cur.i++
            }
            lastCmd = cmd
        }
        return out
    }
}

/** Embedded 24x24 Lucide/Phosphor SVG path catalogue (zero external drawable/emoji/font dependencies). */
object FreedomIconPaths {
    private val rawPaths: Map<FreedomIconId, String> = mapOf(
        FreedomIconId.SHIELD_CHECK to "M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z M9 12l2 2 4-4",
        FreedomIconId.SHIELD_OFF to "m2 2 20 20 M5 5a1 1 0 0 0-1 1v7c0 5 3.5 7.5 7.67 8.94a1 1 0 0 0 .67.01c2.35-.82 4.48-1.97 5.9-3.71 M9.309 3.652A12.252 12.252 0 0 0 11.24 2.28a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1v7a9.784 9.784 0 0 1-.08 1.264",
        FreedomIconId.RADAR to "M19.07 4.93A10 10 0 0 0 6.99 3.34 M4 6h.01 M2.29 9.62A10 10 0 1 0 21.31 8.35 M16.24 7.76A6 6 0 1 0 8.23 16.67 M12 18h.01 M17.99 11.66A6 6 0 0 1 15.77 16.67 M12 10a2 2 0 1 0 0 4a2 2 0 1 0 0-4z M13.41 10.59 19.07 4.93",
        FreedomIconId.SLIDERS to "M21 4h-7 M10 4H3 M21 12h-9 M8 12H3 M21 20h-5 M12 20H3 M14 2v4 M8 10v4 M16 18v4",
        FreedomIconId.ACTIVITY to "M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2",
        FreedomIconId.TERMINAL to "m4 17 6-6-6-6 M12 19h8",
        FreedomIconId.GLOBE to "M12 2a10 10 0 1 0 0 20a10 10 0 1 0 0-20z M12 2a14.5 14.5 0 0 0 0 20a14.5 14.5 0 0 0 0-20 M2 12h20",
        FreedomIconId.ZAP to "M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z",
        FreedomIconId.SERVER to "M4 2h16a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2z M4 14h16a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-4a2 2 0 0 1 2-2z M6 6h.01 M6 18h.01",
        FreedomIconId.SPLIT to "M16 3h5v5 M8 3H3v5 M12 22v-8.3a4 4 0 0 0-1.172-2.872L3 3 M15 9l6-6",
        FreedomIconId.WIFI to "M12 20h.01 M2 8.82a15 15 0 0 1 20 0 M5 12.859a10 10 0 0 1 14 0 M8.5 16.429a5 5 0 0 1 7 0",
        FreedomIconId.ETHERNET to "m15 20 3-3h2a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h2l3 3z M6 8v1 M10 8v1 M14 8v1 M18 8v1",
        FreedomIconId.EYE_OFF to "M10.733 5.076a10.744 10.744 0 0 1 11.205 6.575 1 1 0 0 1 0 .696 10.747 10.747 0 0 1-1.444 2.49 M14.084 14.158a3 3 0 0 1-4.242-4.242 M17.479 17.499a10.75 10.75 0 0 1-15.417-5.151 1 1 0 0 1 0-.696 10.75 10.75 0 0 1 4.446-5.143 M2 2l20 20",
        FreedomIconId.LINK_2_OFF to "M9 17H7A5 5 0 0 1 7 7 M15 7h2a5 5 0 0 1 4 8 M8 12h4 M2 2l20 20",
        FreedomIconId.FINGERPRINT to "M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4 M14 13.12c0 2.38 0 6.38-1 8.88 M17.29 21.02c.12-.6.43-2.3.5-3.02 M2 12a10 10 0 0 1 18-6 M2 16h.01 M21.8 16c.2-2 .131-5.354 0-6 M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2 M8.65 22c.21-.66.45-1.32.57-2 M9 6.8a6 6 0 0 1 9 5.2v2",
        FreedomIconId.MAP_PIN_OFF to "M12.75 7.09a3 3 0 0 1 2.16 2.16 M17.072 17.072c-1.634 2.17-3.527 3.912-4.471 4.727a1 1 0 0 1-1.202 0C9.539 20.193 4 14.993 4 10a8 8 0 0 1 1.432-4.568 M2 2l20 20 M8.475 2.818A8 8 0 0 1 20 10c0 1.183-.31 2.377-.81 3.533 M9.13 9.13a3 3 0 0 0 3.74 3.74",
        FreedomIconId.LOCK to "M5 11h14a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2z M7 11V7a5 5 0 0 1 10 0v4",
        FreedomIconId.KEY_ROUND to "M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z M16.5 7.5a.5.5 0 1 0 0 1a.5.5 0 1 0 0-1z",
        FreedomIconId.PLAY to "M6 4l14 8-14 8V4z",
        FreedomIconId.SQUARE to "M5 3h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z",
        FreedomIconId.REFRESH_CW to "M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8 M21 3v5h-5 M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16 M8 16H3v5",
        FreedomIconId.COPY to "M10 8h10a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H10a2 2 0 0 1-2-2V10a2 2 0 0 1 2-2z M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2",
        FreedomIconId.DOWNLOAD to "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4 M7 10l5 5 5-5 M12 15V3",
        FreedomIconId.CHECK_CIRCLE to "M12 2a10 10 0 1 0 0 20a10 10 0 1 0 0-20z M9 12l2 2 4-4",
        FreedomIconId.ALERT_TRIANGLE to "m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3 M12 9v4 M12 17h.01",
        FreedomIconId.INFO to "M12 2a10 10 0 1 0 0 20a10 10 0 1 0 0-20z M12 16v-4 M12 8h.01",
        FreedomIconId.EXTERNAL_LINK to "M15 3h6v6 M10 14 21 3 M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6",
        FreedomIconId.ARROW_DOWN to "M12 5v14 M19 12l-7 7-7-7",
        FreedomIconId.ARROW_UP to "M12 19V5 M5 12l7-7 7 7",
        FreedomIconId.CHEVRON_DOWN to "m6 9 6 6 6-6",
        FreedomIconId.CHEVRON_UP to "m18 15-6-6-6 6",
        FreedomIconId.BUG to "m8 2 1.88 1.88 M14.12 3.88 16 2 M9 7.13v-1a3.003 3.003 0 1 1 6 0v1 M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6 M12 20v-9 M6.53 9C4.6 8.8 3 7.1 3 5 M6 13H2 M3 21c0-2.1 1.7-3.9 3.8-4 M20.97 5c0 2.1-1.6 3.8-3.5 4 M22 13h-4 M17.2 17c2.1.1 3.8 1.9 3.8 4",
        FreedomIconId.SPARKLES to "M9.937 15.5A2 2 0 0 0 8.5 14.063l-6.135-1.582a.5.5 0 0 1 0-.962L8.5 9.936A2 2 0 0 0 9.937 8.5l1.582-6.135a.5.5 0 0 1 .963 0L14.063 8.5A2 2 0 0 0 15.5 9.937l6.135 1.581a.5.5 0 0 1 0 .964L15.5 14.063a2 2 0 0 0-1.437 1.437l-1.582 6.135a.5.5 0 0 1-.963 0z M20 3v4 M22 5h-4 M4 17v2 M5 18H3",
        FreedomIconId.CPU to "M6 4h12a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z M9 9h6v6H9z M15 2v2 M15 20v2 M2 15h2 M2 9h2 M20 15h2 M20 9h2 M9 2v2 M9 20v2",
    )

    private val parsedCache = ConcurrentHashMap<FreedomIconId, List<SvgCmd>>()

    fun pathData(id: FreedomIconId): String = rawPaths[id] ?: "M12 2a10 10 0 1 0 0 20a10 10 0 1 0 0-20z"

    fun commands(id: FreedomIconId): List<SvgCmd> =
        parsedCache.computeIfAbsent(id) { SvgPathParser.parse(pathData(it)) }
}

// ------------------------------------------------------------------ global volunteer & censorship telemetry (RIPE Atlas, OONI, M-Lab, Cloudflare)

data class RipeProbeSummary(
    val countryCode: String,
    val connectedCount: Int,
    val distinctAsns: Int,
    val sampleAsnNames: List<String>,
    val queryMs: Long,
    val ok: Boolean,
    val error: String = "",
)

data class OoniMeasurement(
    val probeCc: String,
    val probeAsn: String,
    val testName: String,
    val input: String,
    val anomaly: Boolean,
    val confirmed: Boolean,
    val failure: Boolean,
    val startTime: String,
)

data class MlabServerInfo(
    val machine: String,
    val site: String,
    val city: String,
    val country: String,
    val queryMs: Long,
    val ok: Boolean,
    val error: String = "",
)

data class CloudflareTraceInfo(
    val ip: String,
    val warp: String,
    val loc: String,
    val colo: String,
    val sni: String,
    val http: String,
    val ok: Boolean,
    val error: String = "",
)

data class GlobalTelemetrySnapshot(
    val collectedAtMs: Long,
    val ripe: RipeProbeSummary,
    val ooni: List<OoniMeasurement>,
    val ooniQueryMs: Long,
    val ooniOk: Boolean,
    val ooniError: String = "",
    val mlab: MlabServerInfo,
    val cloudflare: CloudflareTraceInfo,
)

/**
 * Queries live public volunteer/internet measurement networks (RIPE Atlas v2, OONI v1,
 * M-Lab Locate v2, and Cloudflare Trace) strictly over HTTPS to corroborate local ISP
 * censorship observations with national hardware probes.
 */
object GlobalCensorshipTelemetry {
    private fun extractObjectsInArray(json: String, arrayKey: String): List<String> {
        val needle = "\"$arrayKey\""
        val kIdx = json.indexOf(needle)
        if (kIdx < 0) return emptyList()
        val arrStart = json.indexOf('[', kIdx + needle.length)
        if (arrStart < 0) return emptyList()
        val out = ArrayList<String>(16)
        var depth = 0
        var objStart = -1
        var inStr = false
        var esc = false
        for (i in (arrStart + 1) until json.length) {
            val c = json[i]
            if (esc) {
                esc = false
                continue
            }
            if (inStr) {
                if (c == '\\') esc = true else if (c == '"') inStr = false
                continue
            }
            when (c) {
                '"' -> inStr = true
                '{' -> {
                    if (depth == 0) objStart = i
                    depth++
                }
                '}' -> {
                    if (depth > 0) depth--
                    if (depth == 0 && objStart >= 0) {
                        out.add(json.substring(objStart, i + 1))
                        objStart = -1
                    }
                }
                ']' -> if (depth == 0) break
            }
        }
        return out
    }

    private fun extractJsonInt(json: String, key: String, startAt: Int = 0): Long? {
        val needle = "\"$key\""
        var idx = json.indexOf(needle, startAt)
        while (idx >= 0) {
            var pos = idx + needle.length
            while (pos < json.length && json[pos].isWhitespace()) pos++
            if (pos < json.length && json[pos] == ':') {
                pos++
                while (pos < json.length && json[pos].isWhitespace()) pos++
                val start = pos
                if (pos < json.length && json[pos] == '-') pos++
                while (pos < json.length && json[pos] in '0'..'9') pos++
                if (pos > start) {
                    return json.substring(start, pos).toLongOrNull()
                }
            }
            idx = json.indexOf(needle, idx + needle.length)
        }
        return null
    }

    fun parseCloudflareTrace(raw: String): CloudflareTraceInfo {
        if (raw.isBlank()) {
            return CloudflareTraceInfo("", "", "", "", "", "", ok = false, error = "boş yanıt")
        }
        val map = HashMap<String, String>()
        for (line in raw.lineSequence()) {
            val eq = line.indexOf('=')
            if (eq > 0) map[line.substring(0, eq).trim().lowercase(java.util.Locale.US)] = line.substring(eq + 1).trim()
        }
        val ip = map["ip"].orEmpty()
        return CloudflareTraceInfo(
            ip = ip,
            warp = map["warp"] ?: "off",
            loc = map["loc"].orEmpty(),
            colo = map["colo"].orEmpty(),
            sni = map["sni"].orEmpty(),
            http = map["http"].orEmpty(),
            ok = ip.isNotEmpty() || map.containsKey("warp"),
            error = if (ip.isEmpty()) "trace alanı eksik" else "",
        )
    }

    fun parseRipeAtlasJson(json: String, countryCode: String = "TR", queryMs: Long = 0L): RipeProbeSummary {
        val count = (extractJsonInt(json, "count") ?: 0L).toInt()
        val objs = extractObjectsInArray(json, "results")
        val asns = LinkedHashSet<String>()
        for (obj in objs) {
            val v4 = extractJsonInt(obj, "asn_v4")
            val v6 = extractJsonInt(obj, "asn_v6")
            if (v4 != null && v4 > 0L) asns.add("AS$v4")
            else if (v6 != null && v6 > 0L) asns.add("AS$v6")
        }
        val effectiveCount = if (count > 0) count else objs.size
        return RipeProbeSummary(
            countryCode = countryCode,
            connectedCount = effectiveCount,
            distinctAsns = asns.size,
            sampleAsnNames = asns.take(5).toList(),
            queryMs = queryMs,
            ok = effectiveCount > 0 || json.contains("\"results\""),
        )
    }

    fun parseOoniJson(json: String): List<OoniMeasurement> {
        val objs = extractObjectsInArray(json, "results")
        val out = ArrayList<OoniMeasurement>(objs.size)
        for (obj in objs) {
            val cc = WarpProvisioner.extractJsonString(obj, "probe_cc").orEmpty()
            val asn = WarpProvisioner.extractJsonString(obj, "probe_asn").orEmpty()
            val testName = WarpProvisioner.extractJsonString(obj, "test_name").orEmpty()
            if (testName.isEmpty() && cc.isEmpty()) continue
            val input = WarpProvisioner.extractJsonString(obj, "input").orEmpty()
            val anomaly = WarpProvisioner.extractJsonBool(obj, "anomaly") ?: false
            val confirmed = WarpProvisioner.extractJsonBool(obj, "confirmed") ?: false
            val failure = WarpProvisioner.extractJsonBool(obj, "failure") ?: false
            val startTime = WarpProvisioner.extractJsonString(obj, "measurement_start_time").orEmpty()
            out.add(OoniMeasurement(cc, asn, testName, input, anomaly, confirmed, failure, startTime))
        }
        return out
    }

    fun parseMlabLocateJson(json: String, queryMs: Long = 0L): MlabServerInfo {
        val objs = extractObjectsInArray(json, "results")
        val first = objs.firstOrNull()
            ?: return MlabServerInfo("", "", "", "", queryMs, ok = false, error = "düğüm bulunamadı")
        val machine = WarpProvisioner.extractJsonString(first, "machine").orEmpty()
        val city = WarpProvisioner.extractJsonString(first, "city").orEmpty()
        val country = WarpProvisioner.extractJsonString(first, "country").orEmpty()
        val site = machine.split('-').getOrNull(2)?.substringBefore('.') ?: ""
        return MlabServerInfo(
            machine = machine,
            site = site,
            city = city,
            country = country,
            queryMs = queryMs,
            ok = machine.isNotEmpty(),
            error = if (machine.isEmpty()) "eksik sunucu adı" else "",
        )
    }

    private fun httpsGet(
        url: String,
        proxyHost: String?,
        proxyPort: Int,
        sslFactory: SSLSocketFactory?,
        timeoutMs: Int,
    ): Pair<Long, String> {
        val t0 = System.nanoTime()
        val proxy = if (!proxyHost.isNullOrBlank() && proxyPort in 1..65535) {
            java.net.Proxy(java.net.Proxy.Type.HTTP, InetSocketAddress(proxyHost, proxyPort))
        } else {
            java.net.Proxy.NO_PROXY
        }
        val conn = java.net.URI(url).toURL().openConnection(proxy) as javax.net.ssl.HttpsURLConnection
        if (sslFactory != null) conn.sslSocketFactory = sslFactory
        conn.connectTimeout = timeoutMs
        conn.readTimeout = timeoutMs
        conn.instanceFollowRedirects = false
        conn.setRequestProperty("User-Agent", "FreedomNetwork/1.0")
        conn.setRequestProperty("Accept", "application/json, text/plain")
        try {
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else (conn.errorStream ?: conn.inputStream)
            val body = stream.bufferedReader(Charsets.UTF_8).use { r ->
                val buf = CharArray(8192)
                val sb = StringBuilder()
                while (sb.length < 131_072) {
                    val k = r.read(buf)
                    if (k <= 0) break
                    sb.append(buf, 0, k)
                }
                sb.toString()
            }
            val ms = ((System.nanoTime() - t0) / 1_000_000L).coerceAtLeast(1L)
            if (code !in 200..299) throw IOException("HTTP $code")
            return ms to body
        } finally {
            runCatching { conn.disconnect() }
        }
    }

    fun collect(
        countryCode: String = "TR",
        proxyHost: String? = null,
        proxyPort: Int = 0,
        sslFactory: SSLSocketFactory? = null,
        timeoutMs: Int = 4500,
    ): GlobalTelemetrySnapshot {
        val cc = countryCode.trim().uppercase(java.util.Locale.US).ifBlank { "TR" }
        val ripeRef = AtomicReference(RipeProbeSummary(cc, 0, 0, emptyList(), 0L, ok = false, error = "zaman aşımı"))
        val ooniListRef = AtomicReference<List<OoniMeasurement>>(emptyList())
        val ooniMetaRef = AtomicReference(Triple(0L, false, "zaman aşımı"))
        val mlabRef = AtomicReference(MlabServerInfo("", "", "", "", 0L, ok = false, error = "zaman aşımı"))
        val cfRef = AtomicReference(CloudflareTraceInfo("", "", "", "", "", "", ok = false, error = "zaman aşımı"))
        val latch = CountDownLatch(4)

        fun launch(name: String, block: () -> Unit) {
            Thread({
                try {
                    block()
                } finally {
                    latch.countDown()
                }
            }, name).apply {
                isDaemon = true
                start()
            }
        }

        launch("freedom-tel-ripe") {
            runCatching {
                val (ms, body) = httpsGet(
                    "https://atlas.ripe.net/api/v2/probes/?country_code=$cc&status=1&page_size=25",
                    proxyHost, proxyPort, sslFactory, timeoutMs,
                )
                ripeRef.set(parseRipeAtlasJson(body, cc, ms))
            }.onFailure { err ->
                ripeRef.set(RipeProbeSummary(cc, 0, 0, emptyList(), 0L, ok = false, error = err.message ?: "hata"))
            }
        }
        launch("freedom-tel-ooni") {
            runCatching {
                val (ms, body) = httpsGet(
                    "https://api.ooni.io/api/v1/measurements?probe_cc=$cc&limit=8",
                    proxyHost, proxyPort, sslFactory, timeoutMs,
                )
                val list = parseOoniJson(body)
                ooniListRef.set(list)
                ooniMetaRef.set(Triple(ms, true, ""))
            }.onFailure { err ->
                ooniMetaRef.set(Triple(0L, false, err.message ?: "hata"))
            }
        }
        launch("freedom-tel-cf") {
            runCatching {
                val (_, body) = httpsGet(
                    "https://cloudflare.com/cdn-cgi/trace",
                    proxyHost, proxyPort, sslFactory, timeoutMs,
                )
                cfRef.set(parseCloudflareTrace(body))
            }.onFailure { err ->
                cfRef.set(CloudflareTraceInfo("", "", "", "", "", "", ok = false, error = err.message ?: "hata"))
            }
        }
        launch("freedom-tel-mlab") {
            runCatching {
                val (ms, body) = httpsGet(
                    "https://locate.measurementlab.net/v2/nearest/ndt/ndt7",
                    proxyHost, proxyPort, sslFactory, timeoutMs,
                )
                mlabRef.set(parseMlabLocateJson(body, ms))
            }.onFailure { err ->
                mlabRef.set(MlabServerInfo("", "", "", "", 0L, ok = false, error = err.message ?: "hata"))
            }
        }

        runCatching { latch.await((timeoutMs + 600).toLong(), TimeUnit.MILLISECONDS) }
        val (oMs, oOk, oErr) = ooniMetaRef.get()
        return GlobalTelemetrySnapshot(
            collectedAtMs = System.currentTimeMillis(),
            ripe = ripeRef.get(),
            ooni = ooniListRef.get(),
            ooniQueryMs = oMs,
            ooniOk = oOk,
            ooniError = oErr,
            mlab = mlabRef.get(),
            cloudflare = cfRef.get(),
        )
    }
}

// ------------------------------------------------------------------ user-mode TUN TCP/UDP/DoH bridge

/**
 * Zero-dependency IPv4 + TCP/UDP packet parser, RFC 1071 / RFC 1624 checksum calculator,
 * packet synthesizer, and L7 Desync segment reassembler for the user-mode TUN bridge.
 */
object IpPackets {
    const val PROTO_ICMP = 1
    const val PROTO_TCP = 6
    const val PROTO_UDP = 17
    const val PROTO_ICMPV6 = 58

    const val TCP_FIN = 0x01
    const val TCP_SYN = 0x02
    const val TCP_RST = 0x04
    const val TCP_PSH = 0x08
    const val TCP_ACK = 0x10

    data class Ipv4Header(
        val ihl: Int,
        val totalLen: Int,
        val ttl: Int,
        val proto: Int,
        val srcIp: Int,
        val dstIp: Int,
    )

    data class TcpSegment(
        val ip: Ipv4Header,
        val srcPort: Int,
        val dstPort: Int,
        val seq: Long,
        val ack: Long,
        val dataOffset: Int,
        val flags: Int,
        val window: Int,
        val payload: ByteArray,
    )

    data class UdpDatagram(
        val ip: Ipv4Header,
        val srcPort: Int,
        val dstPort: Int,
        val payload: ByteArray,
    )

    fun u8(b: ByteArray, off: Int): Int = b[off].toInt() and 0xFF
    fun u16(b: ByteArray, off: Int): Int = ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)
    fun u32(b: ByteArray, off: Int): Long =
        ((b[off].toLong() and 0xFFL) shl 24) or
            ((b[off + 1].toLong() and 0xFFL) shl 16) or
            ((b[off + 2].toLong() and 0xFFL) shl 8) or
            (b[off + 3].toLong() and 0xFFL)

    fun putU16(b: ByteArray, off: Int, v: Int) {
        b[off] = ((v ushr 8) and 0xFF).toByte()
        b[off + 1] = (v and 0xFF).toByte()
    }

    fun putU32(b: ByteArray, off: Int, v: Long) {
        b[off] = ((v ushr 24) and 0xFFL).toByte()
        b[off + 1] = ((v ushr 16) and 0xFFL).toByte()
        b[off + 2] = ((v ushr 8) and 0xFFL).toByte()
        b[off + 3] = (v and 0xFFL).toByte()
    }

    fun ipToBytes(ip: Int): ByteArray = byteArrayOf(
        ((ip ushr 24) and 0xFF).toByte(),
        ((ip ushr 16) and 0xFF).toByte(),
        ((ip ushr 8) and 0xFF).toByte(),
        (ip and 0xFF).toByte(),
    )

    fun ipToString(ip: Int): String =
        "${(ip ushr 24) and 0xFF}.${(ip ushr 16) and 0xFF}.${(ip ushr 8) and 0xFF}.${ip and 0xFF}"

    fun parseIpLiteral(s: String): Int? {
        val parts = s.trim().substringBefore(':').split('.')
        if (parts.size != 4) return null
        var acc = 0
        for (p in parts) {
            val n = p.toIntOrNull() ?: return null
            if (n !in 0..255) return null
            acc = (acc shl 8) or n
        }
        return acc
    }

    fun parseIpv4(raw: ByteArray): Ipv4Header? {
        if (raw.size < 20) return null
        val ver = (raw[0].toInt() ushr 4) and 0x0F
        if (ver != 4) return null
        val ihl = (raw[0].toInt() and 0x0F) * 4
        if (ihl < 20 || raw.size < ihl) return null
        val totalLen = u16(raw, 2)
        if (totalLen < ihl || totalLen > raw.size) return null
        val ttl = u8(raw, 8)
        val proto = u8(raw, 9)
        val srcIp = u32(raw, 12).toInt()
        val dstIp = u32(raw, 16).toInt()
        return Ipv4Header(ihl, totalLen, ttl, proto, srcIp, dstIp)
    }

    fun parseTcp(raw: ByteArray, ip: Ipv4Header? = parseIpv4(raw)): TcpSegment? {
        val ip_ = ip ?: return null
        if (ip.proto != PROTO_TCP || ip.totalLen < ip.ihl + 20) return null
        val base = ip.ihl
        val dataOff = ((raw[base + 12].toInt() ushr 4) and 0x0F) * 4
        if (dataOff < 20 || ip.totalLen < base + dataOff) return null
        val srcPort = u16(raw, base)
        val dstPort = u16(raw, base + 2)
        val seq = u32(raw, base + 4)
        val ack = u32(raw, base + 8)
        val flags = u8(raw, base + 13)
        val window = u16(raw, base + 14)
        val payload = raw.copyOfRange(base + dataOff, ip.totalLen)
        return TcpSegment(ip, srcPort, dstPort, seq, ack, dataOff, flags, window, payload)
    }

    fun parseUdp(raw: ByteArray, ip: Ipv4Header? = null): UdpDatagram? {
        val ip = ip ?: parseIpv4(raw) ?: return null
        if (ip.proto != PROTO_UDP || ip.totalLen < ip.ihl + 8) return null
        val base = ip.ihl
        val srcPort = u16(raw, base)
        val dstPort = u16(raw, base + 2)
        val udpLen = u16(raw, base + 4)
        val end = minOf(ip.totalLen, if (udpLen >= 8) base + udpLen else ip.totalLen)
        if (end < base + 8) return null
        val payload = raw.copyOfRange(base + 8, end)
        return UdpDatagram(ip, srcPort, dstPort, payload)
    }

    /** RFC 1071 16-bit one's-complement checksum over `buf[off until off + len]`. */
    fun ipv4Checksum(buf: ByteArray, off: Int = 0, len: Int = buf.size - off): Int {
        var sum = 0L
        var i = 0
        while (i + 1 < len) {
            sum += u16(buf, off + i).toLong()
            i += 2
        }
        if (i < len) {
            sum += ((buf[off + i].toInt() and 0xFF) shl 8).toLong()
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFFL) + (sum ushr 16)
        }
        return (sum.inv() and 0xFFFFL).toInt()
    }

    /** Computes or verifies TCP/UDP transport checksum over IPv4 pseudo-header + L4 segment. */
    fun transportChecksumV4(
        srcIp: Int,
        dstIp: Int,
        proto: Int,
        buf: ByteArray,
        off: Int = 0,
        len: Int = buf.size - off,
    ): Int {
        var sum = 0L
        sum += ((srcIp ushr 16) and 0xFFFF).toLong()
        sum += (srcIp and 0xFFFF).toLong()
        sum += ((dstIp ushr 16) and 0xFFFF).toLong()
        sum += (dstIp and 0xFFFF).toLong()
        sum += (proto and 0xFF).toLong()
        sum += (len and 0xFFFF).toLong()
        var i = 0
        while (i + 1 < len) {
            sum += u16(buf, off + i).toLong()
            i += 2
        }
        if (i < len) {
            sum += ((buf[off + i].toInt() and 0xFF) shl 8).toLong()
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFFL) + (sum ushr 16)
        }
        return (sum.inv() and 0xFFFFL).toInt()
    }

    /** Skips a (possibly compressed) DNS name starting at [pos]; returns the offset after it or -1. */
    private fun skipDnsName(msg: ByteArray, start: Int): Int {
        var pos = start
        var guard = 0
        while (pos < msg.size && guard++ < 128) {
            val len = msg[pos].toInt() and 0xFF
            when {
                len == 0 -> return pos + 1
                (len and 0xC0) == 0xC0 -> return if (pos + 2 <= msg.size) pos + 2 else -1
                (len and 0xC0) != 0 -> return -1
                else -> pos += 1 + len
            }
        }
        return -1
    }

    /**
     * Extracts A (4-byte) and AAAA (16-byte) RDATA from the answer section of a DNS response.
     * Returns null when the message is malformed.
     */
    fun dnsAnswerAddresses(msg: ByteArray): List<ByteArray>? {
        if (msg.size < 12) return null
        val qd = u16(msg, 4)
        val an = u16(msg, 6)
        var pos = 12
        repeat(qd) {
            pos = skipDnsName(msg, pos)
            if (pos < 0 || pos + 4 > msg.size) return null
            pos += 4
        }
        val out = ArrayList<ByteArray>()
        repeat(an) {
            pos = skipDnsName(msg, pos)
            if (pos < 0 || pos + 10 > msg.size) return null
            val type = u16(msg, pos)
            val rdLen = u16(msg, pos + 8)
            pos += 10
            if (pos + rdLen > msg.size) return null
            if ((type == 1 && rdLen == 4) || (type == 28 && rdLen == 16)) {
                out.add(msg.copyOfRange(pos, pos + rdLen))
            }
            pos += rdLen
        }
        return out
    }

    /**
     * True when a DNS response points to a known ISP block/warning page, sinkhole, or
     * private/link-local/CGNAT DNS-rebinding target (`195.175.254.0/24`, `127/8`, `10/8`,
     * `172.16/12`, `192.168/16`, `169.254/16`, `100.64/10`, `::`, `::1`, `fe80::/10`, `fc00::/7`,
     * or `2a01:358:4014:a00::/64`).
     */
    fun containsPoisonedDns(payload: ByteArray): Boolean {
        val addrs = dnsAnswerAddresses(payload) ?: return false
        for (a in addrs) {
            val b0 = a[0].toInt() and 0xFF
            if (a.size == 4) {
                val b1 = a[1].toInt() and 0xFF
                val b2 = a[2].toInt() and 0xFF
                if (b0 == 195 && b1 == 175 && b2 == 254) return true
                if (b0 == 127 || b0 == 10 || b0 == 0) return true
                if (b0 == 172 && b1 in 16..31) return true
                if (b0 == 192 && b1 == 168) return true
                if (b0 == 169 && b1 == 254) return true
                if (b0 == 100 && b1 in 64..127) return true
            } else {
                if (a.copyOfRange(0, 15).all { it.toInt() == 0 }) return true // :: and ::1
                if (b0 == 0xFE && (a[1].toInt() and 0xC0) == 0x80) return true // fe80::/10
                if ((b0 and 0xFE) == 0xFC) return true // fc00::/7
                val tt = byteArrayOf(0x2a, 0x01, 0x03, 0x58, 0x40, 0x14, 0x0a, 0x00)
                if (a.copyOfRange(0, 8).contentEquals(tt)) return true
            }
        }
        return false
    }

    /** Smallest TTL found in the answer section (seconds), or null. */
    fun dnsMinTtl(msg: ByteArray): Long? {
        if (msg.size < 12) return null
        val qd = u16(msg, 4)
        val an = u16(msg, 6)
        var pos = 12
        repeat(qd) {
            pos = skipDnsName(msg, pos)
            if (pos < 0 || pos + 4 > msg.size) return null
            pos += 4
        }
        var min: Long? = null
        repeat(an) {
            pos = skipDnsName(msg, pos)
            if (pos < 0 || pos + 10 > msg.size) return min
            val ttl = u32(msg, pos + 4)
            val rdLen = u16(msg, pos + 8)
            min = if (min == null) ttl else minOf(min!!, ttl)
            pos += 10 + rdLen
        }
        return min
    }

    /**
     * Synthesizes an ICMPv4 Destination Unreachable (Type 3, Code 3 port unreachable) for an
     * outgoing IPv4 packet, so e.g. QUIC (UDP 443) clients fall back to TCP immediately.
     */
    fun buildIcmpv4Unreachable(origPacket: ByteArray, code: Int = 3): ByteArray? {
        val ip = parseIpv4(origPacket) ?: return null
        val quoteLen = minOf(origPacket.size, ip.ihl + 8)
        val icmpLen = 8 + quoteLen
        val out = ByteArray(20 + icmpLen)
        out[0] = 0x45
        putU16(out, 2, out.size)
        out[8] = 64
        out[9] = PROTO_ICMP.toByte()
        putU32(out, 12, ip.dstIp.toLong() and 0xFFFFFFFFL)
        putU32(out, 16, ip.srcIp.toLong() and 0xFFFFFFFFL)
        putU16(out, 10, checksum(out, 0, 20))
        out[20] = 3
        out[21] = code.toByte()
        System.arraycopy(origPacket, 0, out, 28, quoteLen)
        putU16(out, 22, checksum(out, 20, icmpLen))
        return out
    }

    /** RFC 1071 Internet checksum over [len] bytes at [off]. */
    fun checksum(buf: ByteArray, off: Int, len: Int): Int {
        var sum = 0L
        var i = 0
        while (i + 1 < len) {
            sum += u16(buf, off + i).toLong()
            i += 2
        }
        if (i < len) sum += ((buf[off + i].toInt() and 0xFF) shl 8).toLong()
        while ((sum ushr 16) != 0L) sum = (sum and 0xFFFFL) + (sum ushr 16)
        return (sum.inv() and 0xFFFFL).toInt()
    }

    /**
     * Locates the SNI host name inside a single TLS ClientHello record. Returns
     * `(offset, length)` of the host bytes within [p], or null.
     */
    fun findClientHelloSni(p: ByteArray): Pair<Int, Int>? {
        if (p.size < 48 || (p[0].toInt() and 0xFF) != 0x16 || (p[5].toInt() and 0xFF) != 0x01) return null
        var pos = 5 + 4 + 2 + 32
        if (pos >= p.size) return null
        pos += 1 + (p[pos].toInt() and 0xFF) // session id
        if (pos + 2 > p.size) return null
        pos += 2 + u16(p, pos) // cipher suites
        if (pos + 1 > p.size) return null
        pos += 1 + (p[pos].toInt() and 0xFF) // compression methods
        if (pos + 2 > p.size) return null
        val extEnd = minOf(p.size, pos + 2 + u16(p, pos))
        pos += 2
        while (pos + 4 <= extEnd) {
            val type = u16(p, pos)
            val len = u16(p, pos + 2)
            if (type == 0 && pos + 9 <= extEnd) {
                val nameLen = u16(p, pos + 7)
                val nameOff = pos + 9
                return if (nameOff + nameLen <= p.size && nameLen > 0) nameOff to nameLen else null
            }
            pos += 4 + len
        }
        return null
    }

    /** Splits [payload] at the given (sorted, deduplicated, in-range) byte offsets. */
    fun splitAt(payload: ByteArray, offsets: Collection<Int>): List<ByteArray> {
        val cuts = offsets.filter { it in 1 until payload.size }.distinct().sorted()
        if (cuts.isEmpty()) return listOf(payload)
        val out = ArrayList<ByteArray>(cuts.size + 1)
        var prev = 0
        for (c in cuts + payload.size) {
            out.add(payload.copyOfRange(prev, c))
            prev = c
        }
        return out
    }

    /**
     * Full stream-level DPI evasion plan for the first client payload of a TCP flow:
     * TCP chunk boundaries from the native engine (if any) plus a guaranteed cut in the middle
     * of the SNI host (TLS) or `Host:` value (HTTP), followed by TLS record-layer
     * fragmentation so even TCP-reassembling middleboxes never see the SNI in one record.
     */
    fun planFirstPayload(payload: ByteArray, nativeChunks: List<ByteArray>): List<ByteArray> {
        val cuts = ArrayList<Int>()
        var acc = 0
        for (i in 0 until nativeChunks.size - 1) {
            acc += nativeChunks[i].size
            cuts.add(acc)
        }
        val sni = findClientHelloSni(payload)
        if (sni != null) {
            cuts.add(sni.first + maxOf(1, sni.second / 2))
            cuts.add(sni.first - 2)
        } else {
            val text = String(payload, 0, minOf(payload.size, 2048), Charsets.ISO_8859_1)
            val h = text.indexOf("\r\nHost:", ignoreCase = true)
            if (h >= 0) {
                cuts.add(h + 2)
                val valStart = h + 7
                val valEnd = text.indexOf("\r\n", valStart).let { if (it < 0) text.length else it }
                cuts.add(valStart + maxOf(1, (valEnd - valStart) / 2))
            } else if (payload.size > 2) {
                cuts.add(2)
            }
        }
        val chunks = splitAt(payload, cuts)
        return if (sni != null) fragmentTlsClientHelloRecords(payload, chunks) else chunks
    }

    /** RFC 4443 / RFC 8200 IPv6 pseudo-header transport checksum. */
    fun transportChecksumV6(
        srcIp: ByteArray,
        dstIp: ByteArray,
        nextHeader: Int,
        buf: ByteArray,
        off: Int = 0,
        len: Int = buf.size - off,
    ): Int {
        var sum = 0L
        for (i in 0 until 16 step 2) {
            sum += u16(srcIp, i).toLong()
            sum += u16(dstIp, i).toLong()
        }
        sum += ((len ushr 16) and 0xFFFF).toLong()
        sum += (len and 0xFFFF).toLong()
        sum += (nextHeader and 0xFF).toLong()
        var i = 0
        while (i + 1 < len) {
            sum += u16(buf, off + i).toLong()
            i += 2
        }
        if (i < len) {
            sum += ((buf[off + i].toInt() and 0xFF) shl 8).toLong()
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFFL) + (sum ushr 16)
        }
        return (sum.inv() and 0xFFFFL).toInt()
    }

    /** Synthesizes an ICMPv6 Destination Unreachable (Type 1, Code 3, RFC 4443) for incoming IPv6 packets so dual-stack apps instantly select IPv4. */
    fun buildIcmpv6Unreachable(origPacket: ByteArray): ByteArray? {
        if (origPacket.size < 40 || ((origPacket[0].toInt() ushr 4) and 0x0F) != 6) return null
        val origSrc = origPacket.copyOfRange(8, 24)
        val origDst = origPacket.copyOfRange(24, 40)
        val invokeLen = minOf(origPacket.size, 1200)
        val icmpBodyLen = 8 + invokeLen
        val totalLen = 40 + icmpBodyLen
        val out = ByteArray(totalLen)
        out[0] = 0x60
        putU16(out, 4, icmpBodyLen)
        out[6] = PROTO_ICMPV6.toByte()
        out[7] = 64
        System.arraycopy(origDst, 0, out, 8, 16)
        System.arraycopy(origSrc, 0, out, 24, 16)
        out[40] = 1 // Type 1: Destination Unreachable
        out[41] = 3 // Code 3: Address Unreachable
        System.arraycopy(origPacket, 0, out, 48, invokeLen)
        val csum = transportChecksumV6(origDst, origSrc, PROTO_ICMPV6, out, 40, icmpBodyLen)
        putU16(out, 42, if (csum == 0) 0xFFFF else csum)
        return out
    }

    /** Synthesizes a valid IPv4 + UDP packet with computed IPv4 and UDP checksums. */
    fun buildIpv4Udp(
        srcIp: Int,
        dstIp: Int,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray,
        ttl: Int = 64,
    ): ByteArray {
        val udpLen = 8 + payload.size
        val totalLen = 20 + udpLen
        val pkt = ByteArray(totalLen)
        pkt[0] = 0x45
        putU16(pkt, 2, totalLen)
        putU16(pkt, 4, 0x2468)
        putU16(pkt, 6, 0x4000)
        pkt[8] = ttl.toByte()
        pkt[9] = PROTO_UDP.toByte()
        putU32(pkt, 12, srcIp.toLong() and 0xFFFFFFFFL)
        putU32(pkt, 16, dstIp.toLong() and 0xFFFFFFFFL)
        putU16(pkt, 10, ipv4Checksum(pkt, 0, 20))

        putU16(pkt, 20, srcPort)
        putU16(pkt, 22, dstPort)
        putU16(pkt, 24, udpLen)
        System.arraycopy(payload, 0, pkt, 28, payload.size)
        val csum = transportChecksumV4(srcIp, dstIp, PROTO_UDP, pkt, 20, udpLen)
        putU16(pkt, 26, if (csum == 0) 0xFFFF else csum)
        return pkt
    }

    /** Synthesizes a valid IPv4 + TCP segment (with optional MSS option on SYN+ACK). */
    fun buildIpv4Tcp(
        srcIp: Int,
        dstIp: Int,
        srcPort: Int,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        window: Int = 65535,
        payload: ByteArray = ByteArray(0),
        mssOption: Int = 0,
        ttl: Int = 64,
    ): ByteArray {
        val tcpHdrLen = if (mssOption > 0) 24 else 20
        val totalLen = 20 + tcpHdrLen + payload.size
        val pkt = ByteArray(totalLen)
        pkt[0] = 0x45
        putU16(pkt, 2, totalLen)
        putU16(pkt, 4, 0x1357)
        putU16(pkt, 6, 0x4000)
        pkt[8] = ttl.toByte()
        pkt[9] = PROTO_TCP.toByte()
        putU32(pkt, 12, srcIp.toLong() and 0xFFFFFFFFL)
        putU32(pkt, 16, dstIp.toLong() and 0xFFFFFFFFL)
        putU16(pkt, 10, ipv4Checksum(pkt, 0, 20))

        putU16(pkt, 20, srcPort)
        putU16(pkt, 22, dstPort)
        putU32(pkt, 24, seq and 0xFFFFFFFFL)
        putU32(pkt, 28, ack and 0xFFFFFFFFL)
        pkt[32] = (((tcpHdrLen / 4) shl 4) and 0xF0).toByte()
        pkt[33] = (flags and 0xFF).toByte()
        putU16(pkt, 34, window)
        if (mssOption > 0) {
            pkt[40] = 0x02
            pkt[41] = 0x04
            putU16(pkt, 42, mssOption)
        }
        if (payload.isNotEmpty()) {
            System.arraycopy(payload, 0, pkt, 20 + tcpHdrLen, payload.size)
        }
        val csum = transportChecksumV4(srcIp, dstIp, PROTO_TCP, pkt, 20, tcpHdrLen + payload.size)
        putU16(pkt, 36, csum)
        return pkt
    }

    /**
     * Extracts genuine split payload chunks in ascending TCP sequence number order from a
     * `DesyncResult` (filtering out low-TTL and BadSum decoy packets meant for raw sockets)
     * so user-mode `VpnService.protect()`ed stream sockets transmit SNI/ECH/Host splits
     * without stream corruption.
     */
    fun extractOrderedStreamChunks(
        origPacket: ByteArray,
        origPayload: ByteArray,
        res: DesyncResult?,
    ): List<ByteArray> {
        if (origPayload.isEmpty()) return emptyList()
        val origIp = parseIpv4(origPacket)
        if (res != null && res.status == Codes.OK && !res.dropped && origIp != null && res.packets.isNotEmpty()) {
            val realSegments = ArrayList<Pair<Long, ByteArray>>()
            for (pkt in res.packets) {
                val ip = parseIpv4(pkt) ?: continue
                if (ip.ttl != origIp.ttl) continue // filter out FakeAutoTtl decoy
                if (transportChecksumV4(ip.srcIp, ip.dstIp, PROTO_TCP, pkt, ip.ihl, ip.totalLen - ip.ihl) != 0) {
                    continue // filter out FakeBadSum decoy
                }
                val tcp = parseTcp(pkt, ip) ?: continue
                if (tcp.payload.isNotEmpty()) {
                    realSegments.add(tcp.seq to tcp.payload)
                }
            }
            if (realSegments.isNotEmpty()) {
                realSegments.sortBy { it.first }
                val total = realSegments.sumOf { it.second.size }
                if (total == origPayload.size) {
                    val combined = ByteArray(total)
                    var pos = 0
                    for ((_, seg) in realSegments) {
                        System.arraycopy(seg, 0, combined, pos, seg.size)
                        pos += seg.size
                    }
                    if (combined.contentEquals(origPayload)) {
                        return realSegments.map { it.second }
                    }
                }
            }
        }
        if (origPayload.size > 2) {
            val splitAt = minOf(2, origPayload.size - 1)
            return listOf(origPayload.copyOfRange(0, splitAt), origPayload.copyOfRange(splitAt, origPayload.size))
        }
        return listOf(origPayload)
    }

    /**
     * Fragments a single TLS 1.2/1.3 `ClientHello` record (`0x16 0x03 0x01..0x04 <len:2>`) across
     * multiple valid `TLSPlaintext` handshake records (RFC 5246 §6.2.1 / RFC 8446 §5.1) aligned
     * with the TCP split chunks so stateful TCP-reassembling ISP middleboxes never see an intact
     * SNI (`0x0000`) or ECH (`0xfe0d`) extension in a single TLS record.
     */
    fun fragmentTlsClientHelloRecords(origPayload: ByteArray, tcpChunks: List<ByteArray>): List<ByteArray> {
        if (origPayload.size < 43 ||
            (origPayload[0].toInt() and 0xFF) != 0x16 ||
            (origPayload[1].toInt() and 0xFF) != 0x03 ||
            (origPayload[2].toInt() and 0xFF) > 0x04 ||
            (origPayload[5].toInt() and 0xFF) != 0x01
        ) {
            return tcpChunks
        }
        val recLen = u16(origPayload, 3)
        if (5 + recLen != origPayload.size || recLen <= 4 || tcpChunks.size <= 1) {
            return tcpChunks
        }
        val hs = origPayload.copyOfRange(5, origPayload.size)
        val splitPoints = ArrayList<Int>()
        splitPoints.add(minOf(4, hs.size - 1))
        var cursor = 0
        for (i in 0 until tcpChunks.size - 1) {
            cursor += tcpChunks[i].size
            val hsOff = cursor - 5
            if (hsOff in 1 until hs.size) {
                splitPoints.add(hsOff)
            }
        }
        val uniqueSplits = splitPoints.distinct().sorted()
        if (uniqueSplits.isEmpty()) return tcpChunks
        val records = ArrayList<ByteArray>(uniqueSplits.size + 1)
        var prev = 0
        for (sp in uniqueSplits + hs.size) {
            if (sp <= prev || sp > hs.size) continue
            val sliceLen = sp - prev
            val rec = ByteArray(5 + sliceLen)
            rec[0] = 0x16
            rec[1] = origPayload[1]
            rec[2] = origPayload[2]
            putU16(rec, 3, sliceLen)
            System.arraycopy(hs, prev, rec, 5, sliceLen)
            records.add(rec)
            prev = sp
        }
        return if (records.size > 1) records else tcpChunks
    }

    /** Extracts the lowercase QNAME from a standard DNS wire query packet, or null. */
    fun parseDnsQuestionName(msg: ByteArray): String? {
        if (msg.size < 13 || u16(msg, 4) == 0) return null
        val sb = StringBuilder()
        var pos = 12
        var guard = 0
        while (pos < msg.size && guard++ < 128) {
            val len = msg[pos].toInt() and 0xFF
            if (len == 0) break
            if ((len and 0xC0) != 0) return null
            if (pos + 1 + len > msg.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            for (i in 1..len) {
                val c = (msg[pos + i].toInt() and 0xFF)
                sb.append(if (c in 65..90) (c + 32).toChar() else c.toChar())
            }
            pos += 1 + len
        }
        return if (sb.isEmpty()) null else sb.toString()
    }

    /** Extracts the DNS QTYPE (e.g. `1`=A, `28`=AAAA) from a standard DNS wire query, or null. */
    fun parseDnsQuestionType(msg: ByteArray): Int? {
        if (msg.size < 13 || u16(msg, 4) == 0) return null
        val end = skipDnsName(msg, 12)
        if (end < 13 || end + 4 > msg.size) return null
        return u16(msg, end)
    }

    /** Synthesizes a fast local NXDOMAIN DNS answer (RCODE=3) preserving query ID and question. */
    fun buildDnsNxdomain(query: ByteArray): ByteArray {
        if (query.size < 12) return query.copyOf()
        val end = skipDnsName(query, 12)
        val qEnd = if (end in 13..(query.size - 4)) end + 4 else query.size
        val out = ByteArray(qEnd)
        System.arraycopy(query, 0, out, 0, qEnd)
        out[2] = ((query[2].toInt() and 0x01) or 0x81).toByte() // QR=1, copy RD
        out[3] = 0x83.toByte() // RA=1, RCODE=3 (NXDOMAIN)
        out[4] = 0; out[5] = if (qEnd > 12) 1 else 0
        out[6] = 0; out[7] = 0
        out[8] = 0; out[9] = 0
        out[10] = 0; out[11] = 0
        return out
    }

    /** Synthesizes an empty NOERROR/NODATA DNS answer (ANCOUNT=0) to suppress AAAA leaks when IPv6 is unbridged. */
    fun buildDnsNodataAaaa(query: ByteArray): ByteArray {
        if (query.size < 12) return query.copyOf()
        val end = skipDnsName(query, 12)
        val qEnd = if (end in 13..(query.size - 4)) end + 4 else query.size
        val out = ByteArray(qEnd)
        System.arraycopy(query, 0, out, 0, qEnd)
        out[2] = ((query[2].toInt() and 0x01) or 0x81).toByte() // QR=1, copy RD
        out[3] = 0x80.toByte() // RA=1, RCODE=0 (NOERROR, NODATA)
        out[4] = 0; out[5] = if (qEnd > 12) 1 else 0
        out[6] = 0; out[7] = 0
        out[8] = 0; out[9] = 0
        out[10] = 0; out[11] = 0
        return out
    }

    private val TRACKER_SUFFIXES = arrayOf(
        "doubleclick.net", "googlesyndication.com", "googleadservices.com", "google-analytics.com",
        "analytics.google.com", "adservice.google.com", "app-measurement.com", "appsflyer.com",
        "adjust.com", "branch.io", "mixpanel.com", "amplitude.com", "hotjar.com",
        "taboola.com", "outbrain.com", "criteo.com", "pubmatic.com", "rubiconproject.com",
        "scorecardresearch.com", "quantserve.com", "unityads.unity3d.com",
        "ads-api.tiktok.com", "analytics.tiktok.com", "ads.reddit.com", "telemetry.mozilla.org",
        "fpjs.io", "fingerprintjs.com", "fingerprint.com", "location.services.mozilla.com",
        "mls.services.mozilla.com", "diagmon.samsung.com", "samsungcloudsolution.com",
        "metrics.icloud.com", "metrics.apple.com", "crashlytics.com", "firebase-settings.crashlytics.com",
        "vortex.data.microsoft.com", "telemetry.microsoft.com", "data.mistat.xiaomi.com",
        "tracking.miui.com", "singular.net", "kochava.com", "inmobi.com", "applovin.com",
        "ironsrc.com", "vungle.com", "sentry.io", "datadoghq.com", "segment.io", "segment.com",
    )

    /** True when [host] matches a known advertising, fingerprinting, geo-beacon, or telemetry domain. */
    fun isTrackerOrAdDomain(host: String): Boolean {
        val h = host.lowercase(java.util.Locale.US).trimEnd('.')
        return TRACKER_SUFFIXES.any { s -> h == s || h.endsWith(".$s") }
    }

    /** True when [payload] is a classic STUN Binding Request / IP Discovery packet (`0x0001`). */
    fun isStunBindingRequest(payload: ByteArray): Boolean {
        if (payload.size < 20) return false
        val msgType = u16(payload, 0)
        if (msgType != 0x0001) return false
        val magic = u32(payload, 4)
        return magic == 0x2112A442L || payload.size == 74
    }

    /** Builds a 74-byte STUN UDP IP Discovery packet (`0x00 0x01 0x00 0x46` + SSRC). */
    fun buildStunIpDiscovery(ssrc: Int, address: String = "", port: Int = 0): ByteArray {
        val pkt = ByteArray(74)
        putU16(pkt, 0, 0x0001)
        putU16(pkt, 2, 70)
        putU32(pkt, 4, ssrc.toLong() and 0xFFFFFFFFL)
        val addrBytes = address.toByteArray(Charsets.UTF_8)
        System.arraycopy(addrBytes, 0, pkt, 8, minOf(addrBytes.size, 63))
        putU16(pkt, 72, port)
        return pkt
    }

    /** Builds a real-time UDP protocol handshake datagram (`0x05` + offline framing magic). */
    fun buildRealtimeUdpHandshake(totalSize: Int = 48): ByteArray {
        val size = maxOf(18, totalSize)
        val pkt = ByteArray(size)
        pkt[0] = 0x05
        val magic = byteArrayOf(
            0x00, 0xFF.toByte(), 0xFF.toByte(), 0x00,
            0xFE.toByte(), 0xFE.toByte(), 0xFE.toByte(), 0xFE.toByte(),
            0xFD.toByte(), 0xFD.toByte(), 0xFD.toByte(), 0xFD.toByte(),
            0x12, 0x34, 0x56, 0x78,
        )
        System.arraycopy(magic, 0, pkt, 1, magic.size)
        pkt[17] = 11
        return pkt
    }

    /** True when [port] is a known STUN/TURN/mDNS/SSDP IP-discovery/local-leak UDP port. */
    fun isLeakRiskUdpPort(port: Int): Boolean =
        port == 3478 || port == 3479 || port == 5349 || port == 5353 || port == 1900 || (port in 19302..19309)

    /** True when [port] is a STUN/TURN TCP port that can expose client IP addresses. */
    fun isLeakRiskTcpPort(port: Int): Boolean =
        port == 3478 || port == 3479 || port == 5349

    private fun csumAdjust16(csum: Int, oldVal: Int, newVal: Int): Int {
        var sum = (csum.inv() and 0xFFFF) + (oldVal.inv() and 0xFFFF) + (newVal and 0xFFFF)
        sum = (sum ushr 16) + (sum and 0xFFFF)
        sum += (sum ushr 16)
        return sum.inv() and 0xFFFF
    }

    private fun csumAdjust32(csum: Int, oldVal: Int, newVal: Int): Int {
        val mid = csumAdjust16(csum, (oldVal ushr 16) and 0xFFFF, (newVal ushr 16) and 0xFFFF)
        return csumAdjust16(mid, oldVal and 0xFFFF, newVal and 0xFFFF)
    }

    /**
     * Layer-3 NAT translation on an IPv4 packet (`srcIp` and/or `dstIp`) with RFC 1624
     * incremental IPv4 and TCP/UDP checksum updates and optional TCP SYN MSS clamping.
     */
    fun rewriteIpv4Nat(
        pkt: ByteArray,
        newSrcIp: Int? = null,
        newDstIp: Int? = null,
        clampMss: Int = 0,
    ): ByteArray? {
        val ip = parseIpv4(pkt) ?: return null
        if (pkt.size < ip.totalLen) return null
        val out = pkt.copyOfRange(0, ip.totalLen)
        var ipCsum = u16(out, 10)
        val proto = ip.proto
        val ihl = ip.ihl
        var l4CsumOff = -1
        var l4Csum = 0
        if (proto == PROTO_TCP && out.size >= ihl + 20) {
            l4CsumOff = ihl + 16
            l4Csum = u16(out, l4CsumOff)
        } else if (proto == PROTO_UDP && out.size >= ihl + 8) {
            l4CsumOff = ihl + 6
            l4Csum = u16(out, l4CsumOff)
        }

        if (newSrcIp != null && newSrcIp != ip.srcIp) {
            putU32(out, 12, newSrcIp.toLong() and 0xFFFFFFFFL)
            ipCsum = csumAdjust32(ipCsum, ip.srcIp, newSrcIp)
            if (l4CsumOff >= 0 && (proto == PROTO_TCP || l4Csum != 0)) {
                l4Csum = csumAdjust32(l4Csum, ip.srcIp, newSrcIp)
            }
        }
        if (newDstIp != null && newDstIp != ip.dstIp) {
            putU32(out, 16, newDstIp.toLong() and 0xFFFFFFFFL)
            ipCsum = csumAdjust32(ipCsum, ip.dstIp, newDstIp)
            if (l4CsumOff >= 0 && (proto == PROTO_TCP || l4Csum != 0)) {
                l4Csum = csumAdjust32(l4Csum, ip.dstIp, newDstIp)
            }
        }
        if (clampMss > 0 && proto == PROTO_TCP && out.size >= ihl + 24) {
            val dataOff = ((out[ihl + 12].toInt() ushr 4) and 0x0F) * 4
            val flags = out[ihl + 13].toInt() and 0xFF
            if ((flags and TCP_SYN) != 0 && dataOff >= 24 && ihl + dataOff <= out.size) {
                var pos = ihl + 20
                val end = ihl + dataOff
                while (pos < end) {
                    val kind = out[pos].toInt() and 0xFF
                    if (kind == 0) break
                    if (kind == 1) {
                        pos++
                        continue
                    }
                    if (pos + 1 >= end) break
                    val optLen = out[pos + 1].toInt() and 0xFF
                    if (optLen < 2 || pos + optLen > end) break
                    if (kind == 2 && optLen == 4 && pos + 4 <= end) {
                        val curMss = u16(out, pos + 2)
                        if (curMss > clampMss) {
                            putU16(out, pos + 2, clampMss)
                            l4Csum = csumAdjust16(l4Csum, curMss, clampMss)
                        }
                        break
                    }
                    pos += optLen
                }
            }
        }
        putU16(out, 10, ipCsum)
        if (l4CsumOff >= 0) {
            if (proto == PROTO_UDP) {
                if (u16(out, l4CsumOff) != 0) {
                    putU16(out, l4CsumOff, if (l4Csum == 0) 0xFFFF else l4Csum)
                }
            } else {
                putU16(out, l4CsumOff, l4Csum)
            }
        }
        return out
    }

    /**
     * Strips privacy-leaking IP/geo/device headers (`X-Forwarded-For`, `Forwarded`, `Via`,
     * `X-Real-IP`, `Client-IP`, `True-Client-IP`, `CF-Connecting-IP`, `X-Geo-Location`,
     * `X-Device-Model`, `X-Requested-With`, etc.) from plaintext HTTP/1.x requests and optionally
     * replaces device identity headers with a synthetic future [DevicePersona].
     */
    private val TRACKING_QUERY_KEYS = setOf(
        "fbclid", "gclid", "gbraid", "wbraid", "dclid", "msclkid", "ttclid",
        "twclid", "yclid", "igshid", "mc_cid", "mc_eid", "_hsenc", "_hsmi",
        "mkt_tok", "ref_src", "ref_url", "spm", "si", "oly_enc_id", "oly_anon_id",
        "vero_id", "wickedid",
    )

    fun stripUrlTrackingParamsFromRequestLine(requestLine: String): Pair<String, Boolean> {
        val sp1 = requestLine.indexOf(' ')
        if (sp1 <= 0) return requestLine to false
        val sp2 = requestLine.indexOf(' ', sp1 + 1)
        if (sp2 <= sp1 + 1) return requestLine to false
        val target = requestLine.substring(sp1 + 1, sp2)
        val qIdx = target.indexOf('?')
        if (qIdx < 0 || qIdx == target.lastIndex) return requestLine to false
        val path = target.substring(0, qIdx)
        val query = target.substring(qIdx + 1)
        val parts = query.split('&')
        val kept = ArrayList<String>(parts.size)
        var stripped = false
        for (part in parts) {
            if (part.isEmpty()) continue
            val eq = part.indexOf('=')
            val key = (if (eq >= 0) part.substring(0, eq) else part).lowercase(java.util.Locale.US)
            if (key.startsWith("utm_") || key in TRACKING_QUERY_KEYS) {
                stripped = true
            } else {
                kept.add(part)
            }
        }
        if (!stripped) return requestLine to false
        val newTarget = if (kept.isEmpty()) path else "$path?${kept.joinToString("&")}"
        return "${requestLine.substring(0, sp1 + 1)}$newTarget${requestLine.substring(sp2)}" to true
    }

    data class HttpSanitizeResult(
        val bytes: ByteArray,
        val modified: Boolean,
        val leakBlocked: Boolean,
        val paramsStripped: Boolean,
        val personaApplied: Boolean,
    )

    fun readBoundedHttpLine(input: InputStream, maxLen: Int = 8192): String {
        val sb = StringBuilder()
        while (true) {
            val c = input.read()
            if (c < 0) throw IOException("EOF")
            if (c == '\n'.code) break
            if (c != '\r'.code && sb.length < maxLen) {
                sb.append(c.toChar())
            }
        }
        return sb.toString()
    }

    fun stripPlainHttpAltSvc(payload: ByteArray): Pair<ByteArray, Boolean> {
        if (payload.size < 16) return payload to false
        if (payload[0].toInt() != 'H'.code || payload[1].toInt() != 'T'.code ||
            payload[2].toInt() != 'T'.code || payload[3].toInt() != 'P'.code
        ) {
            return payload to false
        }
        val headText = String(payload, 0, minOf(payload.size, 8192), Charsets.ISO_8859_1)
        val hdrEnd = headText.indexOf("\r\n\r\n")
        if (hdrEnd <= 0) return payload to false
        val lines = headText.substring(0, hdrEnd).split("\r\n")
        if (lines.isEmpty() || !lines[0].startsWith("HTTP/1.")) return payload to false
        var stripped = false
        val kept = ArrayList<String>(lines.size)
        kept.add(lines[0])
        for (i in 1 until lines.size) {
            val line = lines[i]
            val lower = line.lowercase(java.util.Locale.US)
            if (lower.startsWith("alt-svc:") && lower.contains("h3")) {
                stripped = true
            } else {
                kept.add(line)
            }
        }
        if (!stripped) return payload to false
        val newHead = (kept.joinToString("\r\n") + "\r\n\r\n").toByteArray(Charsets.ISO_8859_1)
        val bodyOff = hdrEnd + 4
        val bodyLen = payload.size - bodyOff
        val out = ByteArray(newHead.size + bodyLen)
        System.arraycopy(newHead, 0, out, 0, newHead.size)
        if (bodyLen > 0) System.arraycopy(payload, bodyOff, out, newHead.size, bodyLen)
        return out to true
    }

    fun sanitizePlainHttpHeadersDetailed(
        payload: ByteArray,
        persona: DevicePersona? = null,
        stripGeoHeaders: Boolean = true,
        stripTrackingParams: Boolean = true,
    ): HttpSanitizeResult {
        val untouched = HttpSanitizeResult(payload, modified = false, leakBlocked = false, paramsStripped = false, personaApplied = false)
        if (payload.size < 16) return untouched
        val b0 = payload[0].toInt() and 0xFF
        if (b0 < 0x41 || b0 > 0x5A) return untouched // not uppercase ASCII HTTP method
        val headText = String(payload, 0, minOf(payload.size, 8192), Charsets.ISO_8859_1)
        val hdrEnd = headText.indexOf("\r\n\r\n")
        if (hdrEnd <= 0) return untouched
        val headerBlock = headText.substring(0, hdrEnd)
        val lines = headerBlock.split("\r\n")
        if (lines.isEmpty() || !lines[0].contains("HTTP/1.")) return untouched
        val spoofUa = persona != null && persona != DevicePersona.OFF
        var leakRemoved = false
        var personaModified = false
        var sawUa = false
        val kept = ArrayList<String>(lines.size + 4)
        val (cleanReqLine, reqChanged) = if (stripTrackingParams) {
            stripUrlTrackingParamsFromRequestLine(lines[0])
        } else {
            lines[0] to false
        }
        if (reqChanged) leakRemoved = true
        kept.add(cleanReqLine)
        for (i in 1 until lines.size) {
            val line = lines[i]
            val lower = line.lowercase(java.util.Locale.US)
            if (lower.startsWith("x-forwarded-for:") ||
                lower.startsWith("forwarded:") ||
                lower.startsWith("via:") ||
                lower.startsWith("x-real-ip:") ||
                lower.startsWith("client-ip:") ||
                lower.startsWith("true-client-ip:") ||
                lower.startsWith("cf-connecting-ip:") ||
                lower.startsWith("x-originating-ip:") ||
                lower.startsWith("x-client-ip:") ||
                (stripGeoHeaders && (
                    lower.startsWith("x-geo-location:") ||
                        lower.startsWith("x-location:") ||
                        lower.startsWith("geo-position:")
                    )) ||
                (spoofUa && (
                    lower.startsWith("x-requested-with:") ||
                        lower.startsWith("x-device-model:") ||
                        lower.startsWith("x-device-brand:")
                    ))
            ) {
                leakRemoved = true
            } else if (spoofUa && lower.startsWith("user-agent:")) {
                kept.add("User-Agent: ${persona!!.userAgent}")
                sawUa = true
                personaModified = true
            } else if (spoofUa && lower.startsWith("sec-ch-ua:")) {
                kept.add("Sec-CH-UA: ${persona!!.secChUa}")
                personaModified = true
            } else if (spoofUa && lower.startsWith("sec-ch-ua-model:")) {
                kept.add("Sec-CH-UA-Model: ${persona!!.secChModel}")
                personaModified = true
            } else if (spoofUa && lower.startsWith("sec-ch-ua-platform:")) {
                kept.add("Sec-CH-UA-Platform: ${persona!!.secChPlatform}")
                personaModified = true
            } else if (spoofUa && lower.startsWith("sec-ch-ua-platform-version:")) {
                kept.add("Sec-CH-UA-Platform-Version: ${persona!!.secChPlatformVersion}")
                personaModified = true
            } else if (spoofUa && lower.startsWith("sec-ch-ua-mobile:")) {
                kept.add("Sec-CH-UA-Mobile: ${persona!!.secChMobile}")
                personaModified = true
            } else if (stripGeoHeaders && spoofUa && lower.startsWith("accept-language:")) {
                kept.add("Accept-Language: en-US,en;q=0.9")
                personaModified = true
            } else {
                kept.add(line)
            }
        }
        if (spoofUa && !sawUa) {
            kept.add("User-Agent: ${persona!!.userAgent}")
            personaModified = true
        }
        val anyModified = leakRemoved || personaModified
        if (!anyModified) return untouched
        val newHead = (kept.joinToString("\r\n") + "\r\n\r\n").toByteArray(Charsets.ISO_8859_1)
        val bodyOff = hdrEnd + 4
        val bodyLen = payload.size - bodyOff
        val out = ByteArray(newHead.size + bodyLen)
        System.arraycopy(newHead, 0, out, 0, newHead.size)
        if (bodyLen > 0) System.arraycopy(payload, bodyOff, out, newHead.size, bodyLen)
        return HttpSanitizeResult(
            bytes = out,
            modified = true,
            leakBlocked = leakRemoved,
            paramsStripped = reqChanged,
            personaApplied = personaModified,
        )
    }

    fun sanitizePlainHttpHeaders(
        payload: ByteArray,
        persona: DevicePersona? = null,
        stripGeoHeaders: Boolean = true,
        stripTrackingParams: Boolean = true,
    ): ByteArray = sanitizePlainHttpHeadersDetailed(payload, persona, stripGeoHeaders, stripTrackingParams).bytes

    /** Backwards-compatible helper stripping forwarding/client-IP headers from HTTP/1.x payloads. */
    fun stripPlainHttpClientIpHeaders(payload: ByteArray): ByteArray =
        sanitizePlainHttpHeaders(payload, null, false)
}

/**
 * Futuristic/fictional HTTP device identity profiles masking real OEM brand & OS headers on plaintext HTTP/proxy traffic.
 */
enum class DevicePersona(
    val id: String,
    val labelTr: String,
    val shortLabel: String,
    val userAgent: String,
    val secChUa: String,
    val secChModel: String,
    val secChPlatform: String,
    val secChPlatformVersion: String,
    val secChMobile: String,
) {
    IPHONE_19_BETA(
        id = "iphone19",
        labelTr = "iPhone 19 Beta · iOS 21.0 (Hayalet Kimlik)",
        shortLabel = "iPhone 19 Beta (iOS 21)",
        userAgent = "Mozilla/5.0 (iPhone19,3; CPU iPhone OS 21_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/21.0 Mobile/25A109 Safari/604.1",
        secChUa = "\"Safari\";v=\"21\", \"Not_A Brand\";v=\"99\"",
        secChModel = "\"iPhone 19 Beta\"",
        secChPlatform = "\"iOS\"",
        secChPlatformVersion = "\"21.0.0\"",
        secChMobile = "?1",
    ),
    ANDROID_19_QUANTUM(
        id = "android19",
        labelTr = "Android 19 Quantum · SDK 39 (Hayalet Kimlik)",
        shortLabel = "Android 19 Quantum",
        userAgent = "Mozilla/5.0 (Linux; Android 19; Quantum-X99) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Mobile Safari/537.36",
        secChUa = "\"Chromium\";v=\"148\", \"Not_A Brand\";v=\"99\"",
        secChModel = "\"Quantum-X99 Beta\"",
        secChPlatform = "\"Android\"",
        secChPlatformVersion = "\"19.0.0\"",
        secChMobile = "?1",
    ),
    PIXEL_14_FUTURE(
        id = "pixel14",
        labelTr = "Pixel 14 Ultra · Android 19 Beta (Hayalet Kimlik)",
        shortLabel = "Pixel 14 Ultra Prototype",
        userAgent = "Mozilla/5.0 (Linux; Android 19; Pixel 14 Ultra Proto) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Mobile Safari/537.36",
        secChUa = "\"Google Chrome\";v=\"149\", \"Not_A Brand\";v=\"99\"",
        secChModel = "\"Pixel 14 Ultra Proto\"",
        secChPlatform = "\"Android\"",
        secChPlatformVersion = "\"19.0.0\"",
        secChMobile = "?1",
    ),
    OFF(
        id = "off",
        labelTr = "Gerçek Cihaz Kimliği (Maskesiz)",
        shortLabel = "Kapalı",
        userAgent = "",
        secChUa = "",
        secChModel = "",
        secChPlatform = "",
        secChPlatformVersion = "",
        secChMobile = "",
    );

    companion object {
        fun fromId(id: String?): DevicePersona =
            values().firstOrNull { it.id == id } ?: IPHONE_19_BETA
    }
}

/**
 * Validated upstream exit relay descriptor for public IP hiding (`socks5://`, `http://`,
 * `https://`, or `tor`/`orbot` shortcut to `127.0.0.1:9050`).
 */
data class ExitRelayConfig(
    val scheme: String,
    val host: String,
    val port: Int,
    val username: String = "",
    val password: String = "",
) {
    fun isLoopback(): Boolean =
        host == "127.0.0.1" || host.equals("localhost", ignoreCase = true) || host == "::1"

    fun label(): String = "${scheme.uppercase(java.util.Locale.US)} $host:$port"

    companion object {
        fun parse(raw: String): ExitRelayConfig? {
            val trimmed = raw.trim()
            if (trimmed.isEmpty()) return null
            if (trimmed.equals("tor", ignoreCase = true) || trimmed.equals("orbot", ignoreCase = true)) {
                return ExitRelayConfig(scheme = "socks5", host = "127.0.0.1", port = 9050)
            }
            val normalized = if ("://" in trimmed) trimmed else "socks5://$trimmed"
            val uri = runCatching { java.net.URI(normalized) }.getOrNull() ?: return null
            val rawScheme = (uri.scheme ?: "socks5").lowercase(java.util.Locale.US)
            val scheme = when (rawScheme) {
                "socks", "socks5", "socks5h" -> "socks5"
                "http" -> "http"
                "https" -> "https"
                else -> return null
            }
            val host = uri.host?.trim('[', ']')?.takeIf { it.isNotEmpty() } ?: return null
            val defaultPort = when (scheme) {
                "socks5" -> 1080
                "https" -> 443
                else -> 8080
            }
            val port = if (uri.port > 0) uri.port else defaultPort
            if (port !in 1..65535) return null
            val userInfo = uri.userInfo.orEmpty()
            val user = userInfo.substringBefore(':', "")
            val pass = if (':' in userInfo) userInfo.substringAfter(':') else ""
            return ExitRelayConfig(scheme, host, port, user, pass)
        }
    }
}

/**
 * RFC 8484 DoH client that needs **no DNS of its own**: endpoints are IP literals
 * (`https://1.1.1.1/dns-query`) or well-known resolver names mapped to their anycast IPs, so
 * the ISP resolver (which may return poisoned sinkhole IPs such as `195.175.254.2`) is never
 * consulted and a VPN TUN cannot recurse into itself. Every socket is passed to
 * [protectSocket] (Android `VpnService.protect`). Requests send minimal zero-fingerprint headers
 * over pooled HTTP/1.1 keep-alive connections and verify server identity via HTTPS SAN rules.
 */
class DirectDohClient(
    private val protectSocket: (Socket) -> Boolean = { true },
    private val sslFactory: SSLSocketFactory = SSLSocketFactory.getDefault() as SSLSocketFactory,
    private val verifier: ((String, SSLSession) -> Boolean)? = null,
) : DohClient, AutoCloseable {
    private class Conn(val key: String, val sock: SSLSocket, val input: java.io.BufferedInputStream, val out: OutputStream)

    private val idle = ConcurrentHashMap<String, java.util.concurrent.ConcurrentLinkedQueue<Conn>>()

    override fun post(url: String, body: ByteArray, timeoutMs: Int): DohResponse {
        val start = System.nanoTime()
        fun rtt() = (System.nanoTime() - start) / 1000
        val uri = runCatching { java.net.URI(url) }.getOrNull() ?: return DohResponse(6, 0, EncProtocol.DOH, null)
        val host = uri.host?.trim('[', ']') ?: return DohResponse(6, 0, EncProtocol.DOH, null)
        val port = if (uri.port > 0) uri.port else 443
        val path = (uri.rawPath ?: "/dns-query").ifEmpty { "/dns-query" }
        val key = "$host:$port"
        for (attempt in 0 until 2) {
            val pooled = if (attempt == 0) idle[key]?.poll() else null
            val conn = pooled ?: try {
                open(host, port, timeoutMs)
            } catch (_: SocketTimeoutException) {
                return DohResponse(2, rtt(), EncProtocol.DOH, null)
            } catch (_: ConnectException) {
                return DohResponse(4, rtt(), EncProtocol.DOH, null)
            } catch (_: SSLHandshakeException) {
                return DohResponse(5, rtt(), EncProtocol.DOH, null)
            } catch (_: IOException) {
                return DohResponse(5, rtt(), EncProtocol.DOH, null)
            }
            try {
                conn.sock.soTimeout = timeoutMs
                val hostHeader = if (host.contains(':')) "[$host]" else host
                val head = "POST $path HTTP/1.1\r\nHost: $hostHeader\r\n" +
                    "Content-Type: application/dns-message\r\nAccept: application/dns-message\r\n" +
                    "Content-Length: ${body.size}\r\nConnection: keep-alive\r\n\r\n"
                conn.out.write(head.toByteArray(Charsets.US_ASCII))
                conn.out.write(body)
                conn.out.flush()
                val (status, headers, respBody) = readResponse(conn.input)
                val keep = !headers["connection"].orEmpty().equals("close", ignoreCase = true)
                if (keep) idle.getOrPut(key) { java.util.concurrent.ConcurrentLinkedQueue() }.offer(conn) else closeConn(conn)
                val type = headers["content-type"].orEmpty()
                return if (status == 200 && type.startsWith("application/dns-message", ignoreCase = true) && respBody.size >= 12) {
                    DohResponse(1, rtt(), EncProtocol.DOH, respBody)
                } else {
                    DohResponse(6, rtt(), EncProtocol.DOH, null)
                }
            } catch (e: IOException) {
                closeConn(conn)
                if (pooled == null) {
                    return DohResponse(if (e is SocketTimeoutException) 2 else 5, rtt(), EncProtocol.DOH, null)
                }
                // stale keep-alive connection: retry once on a fresh one
            }
        }
        return DohResponse(5, rtt(), EncProtocol.DOH, null)
    }

    private fun open(host: String, port: Int, timeoutMs: Int): Conn {
        val ip = IpPackets.parseIpLiteral(host)?.let { InetAddress.getByAddress(IpPackets.ipToBytes(it)) }
            ?: BOOTSTRAP[host.lowercase(java.util.Locale.US)]?.let { InetAddress.getByAddress(IpPackets.ipToBytes(IpPackets.parseIpLiteral(it)!!)) }
            ?: InetAddress.getByName(host)
        val raw = Socket()
        try {
            raw.bind(null)
            protectSocket(raw)
            raw.tcpNoDelay = true
            raw.connect(InetSocketAddress(ip, port), timeoutMs)
            raw.soTimeout = timeoutMs
            val ssl = sslFactory.createSocket(raw, host, port, true) as SSLSocket
            val params = ssl.sslParameters
            params.endpointIdentificationAlgorithm = "HTTPS"
            ssl.sslParameters = params
            ssl.startHandshake()
            val v = verifier
            if (v != null && !v(host, ssl.session)) {
                runCatching { ssl.close() }
                throw SSLPeerUnverifiedException("DoH host verification failed: $host")
            }
            return Conn("$host:$port", ssl, java.io.BufferedInputStream(ssl.inputStream), java.io.BufferedOutputStream(ssl.outputStream))
        } catch (e: IOException) {
            runCatching { raw.close() }
            throw e
        }
    }

    private fun readLine(input: java.io.InputStream): String = IpPackets.readBoundedHttpLine(input)

    private fun readExact(input: java.io.InputStream, n: Int): ByteArray {
        val out = ByteArray(n)
        var r = 0
        while (r < n) {
            val k = input.read(out, r, n - r)
            if (k < 0) throw IOException("EOF")
            r += k
        }
        return out
    }

    private fun readResponse(input: java.io.InputStream): Triple<Int, Map<String, String>, ByteArray> {
        val statusLine = readLine(input)
        val status = statusLine.split(' ').getOrNull(1)?.toIntOrNull() ?: throw IOException("bad status")
        val headers = HashMap<String, String>()
        while (true) {
            val line = readLine(input)
            if (line.isEmpty()) break
            val i = line.indexOf(':')
            if (i > 0) headers[line.substring(0, i).trim().lowercase(java.util.Locale.US)] = line.substring(i + 1).trim()
        }
        val body = if (headers["transfer-encoding"].orEmpty().contains("chunked", ignoreCase = true)) {
            val acc = ByteArrayOutputStream()
            while (true) {
                val size = readLine(input).substringBefore(';').trim().toIntOrNull(16) ?: throw IOException("bad chunk")
                if (size == 0) {
                    while (readLine(input).isNotEmpty()) { /* trailers */ }
                    break
                }
                if (acc.size() + size > Wire.MAX_BYTES) throw IOException("too large")
                acc.write(readExact(input, size))
                readLine(input)
            }
            acc.toByteArray()
        } else {
            val len = headers["content-length"]?.toIntOrNull() ?: throw IOException("no length")
            if (len < 0 || len > Wire.MAX_BYTES) throw IOException("bad length")
            readExact(input, len)
        }
        return Triple(status, headers, body)
    }

    private fun closeConn(c: Conn) {
        runCatching { c.sock.close() }
    }

    override fun close() {
        for (q in idle.values) while (true) closeConn(q.poll() ?: break)
        idle.clear()
    }

    companion object {
        /** Anycast addresses of public resolvers, used instead of a DNS lookup for their names. */
        val BOOTSTRAP = mapOf(
            "cloudflare-dns.com" to "1.1.1.1",
            "one.one.one.one" to "1.1.1.1",
            "security.cloudflare-dns.com" to "1.1.1.2",
            "dns.google" to "8.8.8.8",
            "dns.google.com" to "8.8.8.8",
            "dns.quad9.net" to "9.9.9.9",
            "dns.adguard-dns.com" to "94.140.14.14",
        )
    }
}

/** Provisioned Cloudflare WARP WireGuard credentials (persisted locally for instant reconnect). */
data class WarpIdentity(
    val privateKeyB64: String,
    val peerPublicKeyB64: String,
    val clientIpv4: String,
    val endpointHost: String,
    val endpointPort: Int = 2408,
    val deviceId: String = "",
    val accessToken: String = "",
    val createdAtMs: Long = System.currentTimeMillis(),
    val clientIdB64: String = "",
    val clientIpv6: String = "",
) {
    fun privateKeyBytes(): ByteArray? = runCatching {
        java.util.Base64.getDecoder().decode(privateKeyB64).takeIf { it.size == 32 }
    }.getOrNull()

    fun peerPublicKeyBytes(): ByteArray? = runCatching {
        java.util.Base64.getDecoder().decode(peerPublicKeyB64).takeIf { it.size == 32 }
    }.getOrNull()

    fun reservedBytes(): ByteArray {
        val raw = runCatching { java.util.Base64.getDecoder().decode(clientIdB64) }.getOrNull()
        return if (raw != null && raw.size >= 3) raw.copyOfRange(0, 3) else byteArrayOf(0, 0, 0)
    }

    fun clientIpInt(): Int? = IpPackets.parseIpLiteral(clientIpv4)

    fun isValid(): Boolean =
        privateKeyBytes() != null &&
            peerPublicKeyBytes() != null &&
            clientIpInt() != null &&
            endpointHost.isNotBlank() &&
            endpointPort in 1..65535

    fun serialize(): String =
        listOf(
            privateKeyB64,
            peerPublicKeyB64,
            clientIpv4,
            endpointHost,
            endpointPort.toString(),
            deviceId,
            accessToken,
            createdAtMs.toString(),
            clientIdB64,
            clientIpv6,
        ).joinToString("|")

    companion object {
        fun deserialize(raw: String?): WarpIdentity? {
            if (raw.isNullOrBlank()) return null
            val p = raw.split('|')
            if (p.size < 5) return null
            val id = WarpIdentity(
                privateKeyB64 = p[0].trim(),
                peerPublicKeyB64 = p[1].trim(),
                clientIpv4 = p[2].trim(),
                endpointHost = p[3].trim(),
                endpointPort = p[4].trim().toIntOrNull() ?: 2408,
                deviceId = p.getOrNull(5)?.trim().orEmpty(),
                accessToken = p.getOrNull(6)?.trim().orEmpty(),
                createdAtMs = p.getOrNull(7)?.trim()?.toLongOrNull() ?: 0L,
                clientIdB64 = p.getOrNull(8)?.trim().orEmpty(),
                clientIpv6 = p.getOrNull(9)?.trim().orEmpty(),
            )
            return if (id.isValid()) id else null
        }
    }
}

/** Zero-config Cloudflare WARP WireGuard account provisioner via pure Rust X25519 + TLS. */
object WarpProvisioner {
    private const val API_HOST = "api.cloudflareclient.com"
    private const val ALT_API_HOST = "api.devices.cloudflare.com"
    private const val API_PATH = "/v0a2158/reg"
    private val FALLBACK_API_IPS = listOf("162.159.137.105", "162.159.138.105", "104.16.80.230", "104.24.4.6")

    internal fun extractJsonString(json: String, key: String, startAt: Int = 0): String? {
        val needle = "\"$key\""
        var idx = json.indexOf(needle, startAt)
        while (idx >= 0) {
            var pos = idx + needle.length
            while (pos < json.length && json[pos].isWhitespace()) pos++
            if (pos < json.length && json[pos] == ':') {
                pos++
                while (pos < json.length && json[pos].isWhitespace()) pos++
                if (pos < json.length && json[pos] == '"') {
                    val end = json.indexOf('"', pos + 1)
                    if (end > pos) return json.substring(pos + 1, end)
                }
            }
            idx = json.indexOf(needle, idx + needle.length)
        }
        return null
    }

    internal fun extractJsonBool(json: String, key: String, startAt: Int = 0): Boolean? {
        val needle = "\"$key\""
        var idx = json.indexOf(needle, startAt)
        while (idx >= 0) {
            var pos = idx + needle.length
            while (pos < json.length && json[pos].isWhitespace()) pos++
            if (pos < json.length && json[pos] == ':') {
                pos++
                while (pos < json.length && json[pos].isWhitespace()) pos++
                if (json.startsWith("true", pos)) return true
                if (json.startsWith("false", pos)) return false
            }
            idx = json.indexOf(needle, idx + needle.length)
        }
        return null
    }

    fun parseRegistrationJson(json: String, privKeyB64: String): WarpIdentity? {
        val deviceId = extractJsonString(json, "id").orEmpty()
        val token = extractJsonString(json, "token").orEmpty()
        val addrIdx = json.indexOf("\"addresses\"")
        val rawV4 = if (addrIdx >= 0) extractJsonString(json, "v4", addrIdx) else extractJsonString(json, "v4")
        val clientIpv4 = rawV4?.substringBefore('/')?.trim().orEmpty()
        val rawV6 = if (addrIdx >= 0) extractJsonString(json, "v6", addrIdx) else null
        val clientIpv6 = rawV6?.substringBefore('/')?.trim().orEmpty()
        val clientIdB64 = extractJsonString(json, "client_id").orEmpty()
        val peersIdx = json.indexOf("\"peers\"")
        val searchFrom = if (peersIdx >= 0) peersIdx else 0
        val peerPub = extractJsonString(json, "public_key", searchFrom).orEmpty()
        val epIdx = json.indexOf("\"endpoint\"", searchFrom)
        val rawEndpoint = if (epIdx >= 0) extractJsonString(json, "v4", epIdx).orEmpty() else "162.159.192.1:2408"
        val cleanEp = rawEndpoint.substringBefore('/')
        val colon = cleanEp.lastIndexOf(':')
        val host = if (colon > 0) cleanEp.substring(0, colon).trim('[', ']') else cleanEp.trim('[', ']')
        val port = if (colon > 0) cleanEp.substring(colon + 1).toIntOrNull() ?: 2408 else 2408
        val id = WarpIdentity(
            privateKeyB64 = privKeyB64,
            peerPublicKeyB64 = peerPub,
            clientIpv4 = clientIpv4,
            endpointHost = host.ifBlank { "162.159.192.1" },
            endpointPort = if (port in 1..65535) port else 2408,
            deviceId = deviceId,
            accessToken = token,
            clientIdB64 = clientIdB64,
            clientIpv6 = clientIpv6,
        )
        return if (id.isValid()) id else null
    }

    private fun readHttpLine(input: InputStream): String = IpPackets.readBoundedHttpLine(input)

    private fun readHttpExact(input: InputStream, n: Int): ByteArray {
        val out = ByteArray(n)
        var r = 0
        while (r < n) {
            val k = input.read(out, r, n - r)
            if (k < 0) throw IOException("EOF")
            r += k
        }
        return out
    }

    private fun httpsJsonRequest(
        ip: InetAddress,
        method: String,
        path: String,
        bodyJson: String,
        bearerToken: String = "",
        protectSocket: (Socket) -> Boolean,
        timeoutMs: Int = 5500,
        apiHost: String = API_HOST,
    ): Pair<Int, String> {
        val raw = Socket()
        var ssl: SSLSocket? = null
        try {
            raw.bind(null)
            protectSocket(raw)
            raw.tcpNoDelay = true
            raw.connect(InetSocketAddress(ip, 443), timeoutMs)
            raw.soTimeout = timeoutMs
            val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
            ssl = factory.createSocket(raw, apiHost, 443, true) as SSLSocket
            val params = ssl.sslParameters
            params.endpointIdentificationAlgorithm = "HTTPS"
            ssl.sslParameters = params
            ssl.startHandshake()

            val bodyBytes = bodyJson.toByteArray(Charsets.UTF_8)
            val sb = StringBuilder()
            sb.append("$method $path HTTP/1.1\r\n")
            sb.append("Host: $apiHost\r\n")
            sb.append("User-Agent: okhttp/3.12.1\r\n")
            sb.append("Accept-Encoding: identity\r\n")
            sb.append("Content-Type: application/json; charset=UTF-8\r\n")
            if (bearerToken.isNotEmpty()) {
                sb.append("Authorization: Bearer $bearerToken\r\n")
            }
            sb.append("Content-Length: ${bodyBytes.size}\r\n")
            sb.append("Connection: close\r\n\r\n")
            val out = ssl.outputStream
            out.write(sb.toString().toByteArray(Charsets.US_ASCII))
            out.write(bodyBytes)
            out.flush()

            val input = java.io.BufferedInputStream(ssl.inputStream)
            val statusLine = readHttpLine(input)
            val code = statusLine.split(' ').getOrNull(1)?.toIntOrNull() ?: 0
            val headers = HashMap<String, String>()
            while (true) {
                val line = readHttpLine(input)
                if (line.isEmpty()) break
                val i = line.indexOf(':')
                if (i > 0) headers[line.substring(0, i).trim().lowercase(java.util.Locale.US)] = line.substring(i + 1).trim()
            }
            val respBytes = if (headers["transfer-encoding"].orEmpty().contains("chunked", ignoreCase = true)) {
                val acc = ByteArrayOutputStream()
                while (true) {
                    val sz = readHttpLine(input).substringBefore(';').trim().toIntOrNull(16) ?: break
                    if (sz == 0) break
                    if (acc.size() + sz > 262144) break
                    acc.write(readHttpExact(input, sz))
                    readHttpLine(input)
                }
                acc.toByteArray()
            } else {
                val cl = headers["content-length"]?.toIntOrNull()
                if (cl != null && cl in 0..262144) {
                    readHttpExact(input, cl)
                } else {
                    val acc = ByteArrayOutputStream()
                    val buf = ByteArray(4096)
                    while (acc.size() < 262144) {
                        val k = input.read(buf)
                        if (k <= 0) break
                        acc.write(buf, 0, k)
                    }
                    acc.toByteArray()
                }
            }
            return code to String(respBytes, Charsets.UTF_8)
        } finally {
            runCatching { ssl?.close() }
            runCatching { raw.close() }
        }
    }

    private fun resolveApiCandidates(protectSocket: (Socket) -> Boolean): List<InetAddress> {
        val out = ArrayList<InetAddress>()
        runCatching {
            DirectDohClient(protectSocket).use { doh ->
                for (hostName in arrayOf(API_HOST, ALT_API_HOST)) {
                    val q = Doh.query(hostName)
                    if (q != null) {
                        val r = doh.post("https://1.1.1.1/dns-query", q, 2500)
                        val b = r.body
                        if (r.transport == 1 && b != null && !IpPackets.containsPoisonedDns(b)) {
                            IpPackets.dnsAnswerAddresses(b)?.forEach { addr ->
                                if (addr.size == 4) runCatching { out.add(InetAddress.getByAddress(addr)) }
                            }
                        }
                    }
                }
            }
        }
        for (hostName in arrayOf(API_HOST, ALT_API_HOST)) {
            runCatching {
                InetAddress.getAllByName(hostName).forEach { a ->
                    if (a is Inet4Address && !a.isLoopbackAddress && !a.isSiteLocalAddress) out.add(a)
                }
            }
        }
        for (ipStr in FALLBACK_API_IPS) {
            IpPackets.parseIpLiteral(ipStr)?.let { v4 ->
                runCatching { out.add(InetAddress.getByAddress(IpPackets.ipToBytes(v4))) }
            }
        }
        return out.distinct()
    }

    fun register(
        protectSocket: (Socket) -> Boolean = { true },
        logger: ((String, String) -> Unit)? = null,
    ): WarpIdentity? {
        if (!Native.available) return null
        val priv = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val pub = Native.wgPublicKey(priv) ?: return null
        if (pub.size != 32) return null
        val privB64 = java.util.Base64.getEncoder().encodeToString(priv)
        val pubB64 = java.util.Base64.getEncoder().encodeToString(pub)
        val df = java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.000'Z'", java.util.Locale.US).apply {
            timeZone = java.util.TimeZone.getTimeZone("UTC")
        }
        val tos = df.format(java.util.Date())
        val payload = "{\"install_id\":\"\",\"tos\":\"$tos\",\"key\":\"$pubB64\",\"fcm_token\":\"\",\"type\":\"Android\",\"model\":\"PC\",\"locale\":\"en_US\"}"

        val candidates = resolveApiCandidates(protectSocket)
        for (apiHost in arrayOf(API_HOST, ALT_API_HOST)) {
            for (ip in candidates) {
                val res = runCatching {
                    httpsJsonRequest(ip, "POST", API_PATH, payload, "", protectSocket, 5000, apiHost)
                }.getOrNull() ?: continue
                val (code, json) = res
                if (code in 200..299 && json.isNotBlank()) {
                    val id = parseRegistrationJson(json, privB64)
                    if (id != null) {
                        val enabled = extractJsonBool(json, "warp_enabled") ?: false
                        if (!enabled && id.deviceId.isNotEmpty() && id.accessToken.isNotEmpty()) {
                            runCatching {
                                httpsJsonRequest(
                                    ip,
                                    "PATCH",
                                    "$API_PATH/${id.deviceId}",
                                    "{\"warp_enabled\":true}",
                                    id.accessToken,
                                    protectSocket,
                                    3500,
                                    apiHost,
                                )
                            }
                        }
                        logger?.invoke("WarpProvisioner", "WARP hesabı hazır (${id.clientIpv4} -> ${id.endpointHost}:${id.endpointPort})")
                        return id
                    }
                }
            }
        }
        logger?.invoke("WarpProvisioner", "WARP kaydı oluşturulamadı (tüm API adayları yanıt vermedi)")
        return null
    }
}

/** Pure-Rust WireGuard UDP tunnel client over `VpnService.protect()`ed `DatagramSocket`. */
class WarpTunnel(
    val identity: WarpIdentity,
    private val protectDatagram: (DatagramSocket) -> Boolean = { true },
    private val logger: ((String, String) -> Unit)? = null,
) : AutoCloseable {
    private val wgHandle = java.util.concurrent.atomic.AtomicLong(0L)
    private val closed = AtomicBoolean(false)
    @Volatile private var socket: DatagramSocket? = null
    @Volatile var activeEndpoint: InetSocketAddress? = null
    @Volatile var established: Boolean = false
    @Volatile var handshakeRttMs: Long = 0L
    @Volatile private var lastRxMs: Long = 0L
    @Volatile private var lastTxMs: Long = 0L
    private var recvThread: Thread? = null
    private var keepaliveThread: Thread? = null

    private fun buildTai64n(): ByteArray {
        val nowNs = System.currentTimeMillis() * 1_000_000L
        val monoNs = lastTaiNs.updateAndGet { prev -> if (nowNs > prev) nowNs else prev + 1L }
        val secs = (monoNs / 1_000_000_000L) + 4611686018427387914L
        val nanos = (monoNs % 1_000_000_000L).toInt()
        val out = ByteArray(12)
        IpPackets.putU32(out, 0, (secs ushr 32) and 0xFFFFFFFFL)
        IpPackets.putU32(out, 4, secs and 0xFFFFFFFFL)
        IpPackets.putU32(out, 8, nanos.toLong() and 0xFFFFFFFFL)
        return out
    }

    private fun buildCandidates(): List<InetSocketAddress> {
        val list = ArrayList<Pair<String, Int>>()
        list.add(identity.endpointHost to identity.endpointPort)
        for (p in intArrayOf(2408, 500, 4500, 1701, 894, 854, 4198, 7152, 8854)) {
            list.add(identity.endpointHost to p)
        }
        for (ip in arrayOf(
            "162.159.192.1", "162.159.193.1", "162.159.195.1",
            "188.114.96.1", "188.114.97.1", "188.114.98.1", "188.114.99.1",
        )) {
            list.add(ip to 2408)
            list.add(ip to 500)
            list.add(ip to 4500)
        }
        return list.distinct().mapNotNull { (h, p) ->
            runCatching { InetSocketAddress(InetAddress.getByName(h), p) }.getOrNull()
        }
    }

    fun connect(timeoutMs: Int = 3500): Boolean {
        if (!Native.available || !identity.isValid()) return false
        val priv = identity.privateKeyBytes() ?: return false
        val peerPub = identity.peerPublicKeyBytes() ?: return false
        val h = Native.wgCreate(priv, peerPub)
        if (h <= 0L) return false
        wgHandle.set(h)
        runCatching { Native.wgSetReserved(h, identity.reservedBytes()) }
        val s = try {
            DatagramSocket().also { ds ->
                protectDatagram(ds)
                runCatching { ds.receiveBufferSize = 262144; ds.sendBufferSize = 262144 }
                ds.soTimeout = 500
            }
        } catch (t: Throwable) {
            Native.wgDestroy(h)
            wgHandle.set(0L)
            return false
        }
        socket = s
        val rng = java.security.SecureRandom()
        val ephPriv = ByteArray(32).also { rng.nextBytes(it) }
        val initPkt = Native.wgHandshakeInit(h, ephPriv, buildTai64n())
        if (initPkt == null || initPkt.size != 148) {
            close()
            return false
        }
        val candidates = buildCandidates()
        val awgPrefaces = runCatching {
            Native.wgBuildAwgPrefaces(2, 48, 96, null)?.let { raw ->
                Wire.decode(raw).bytesAll(Tags.Desync.OUT_PACKET)
            }
        }.getOrNull().orEmpty()
        for (ep in candidates.take(4)) {
            for (junk in awgPrefaces) {
                runCatching { s.send(DatagramPacket(junk, junk.size, ep)) }
            }
        }
        val t0Ms = System.currentTimeMillis()
        for (ep in candidates) {
            runCatching { s.send(DatagramPacket(initPkt, initPkt.size, ep)) }
        }
        val deadline = System.currentTimeMillis() + timeoutMs
        val buf = ByteArray(2048)
        while (!closed.get() && System.currentTimeMillis() < deadline) {
            val dp = DatagramPacket(buf, buf.size)
            val got = try {
                s.receive(dp)
                true
            } catch (_: SocketTimeoutException) {
                false
            } catch (_: Throwable) {
                break
            }
            if (!got || dp.length < 16) continue
            val pkt = buf.copyOf(dp.length)
            when (Native.wgConsumeResponse(h, pkt)) {
                0 -> {
                    activeEndpoint = dp.socketAddress as? InetSocketAddress ?: candidates.firstOrNull()
                    established = true
                    val now = System.currentTimeMillis()
                    handshakeRttMs = (now - t0Ms).coerceAtLeast(1L)
                    lastRxMs = now
                    lastTxMs = now
                    sendIpPacket(ByteArray(0))
                    logger?.invoke(
                        "WarpTunnel",
                        "WARP WireGuard el sıkışması tamamlandı (${handshakeRttMs}ms) -> ${activeEndpoint?.hostString}:${activeEndpoint?.port}",
                    )
                    return true
                }
                1 -> {
                    val eph2 = ByteArray(32).also { rng.nextBytes(it) }
                    Native.wgHandshakeInit(h, eph2, buildTai64n())?.let { retryPkt ->
                        dp.socketAddress?.let { ep ->
                            runCatching { s.send(DatagramPacket(retryPkt, retryPkt.size, ep)) }
                        }
                    }
                }
            }
        }
        logger?.invoke("WarpTunnel", "WARP WireGuard UDP el sıkışması zaman aşımına uğradı")
        close()
        return false
    }

    fun startLoops(onDecryptedIpPacket: (ByteArray) -> Unit) {
        val s = socket ?: return
        runCatching { s.soTimeout = 30_000 }
        recvThread = Thread({
            val buf = ByteArray(65535)
            while (!closed.get() && established) {
                val dp = DatagramPacket(buf, buf.size)
                try {
                    s.receive(dp)
                    if (dp.length < 32) continue
                    val h = wgHandle.get()
                    if (h <= 0L) break
                    val dec = Native.wgDecrypt(h, buf.copyOf(dp.length)) ?: continue
                    lastRxMs = System.currentTimeMillis()
                    if (dec.isNotEmpty()) {
                        onDecryptedIpPacket(dec)
                    }
                } catch (_: SocketTimeoutException) {
                    if (System.currentTimeMillis() - lastRxMs > 125_000L) {
                        rekeyOnce()
                    }
                } catch (_: Throwable) {
                    if (!closed.get()) break
                }
            }
        }, "freedom-wg-rx").apply {
            isDaemon = true
            start()
        }
        keepaliveThread = Thread({
            val rng = java.security.SecureRandom()
            while (!closed.get() && established) {
                try {
                    Thread.sleep(18_000L + rng.nextInt(6_001).toLong())
                } catch (_: InterruptedException) {
                    break
                }
                if (closed.get() || !established) break
                if (System.currentTimeMillis() - lastTxMs >= 18_000L) {
                    sendIpPacket(ByteArray(0))
                }
            }
        }, "freedom-wg-keepalive").apply {
            isDaemon = true
            start()
        }
    }

    private fun rekeyOnce() {
        val h = wgHandle.get()
        val s = socket ?: return
        val ep = activeEndpoint ?: return
        if (h <= 0L || closed.get()) return
        val eph = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val initPkt = Native.wgHandshakeInit(h, eph, buildTai64n()) ?: return
        runCatching { s.send(DatagramPacket(initPkt, initPkt.size, ep)) }
    }

    fun sendIpPacket(ipPacket: ByteArray): Boolean {
        val h = wgHandle.get()
        val s = socket
        val ep = activeEndpoint
        if (h <= 0L || s == null || ep == null || !established || closed.get()) return false
        val wg = Native.wgEncrypt(h, ipPacket) ?: return false
        return try {
            s.send(DatagramPacket(wg, wg.size, ep))
            lastTxMs = System.currentTimeMillis()
            true
        } catch (_: Throwable) {
            false
        }
    }

    fun reprotect() {
        socket?.let { runCatching { protectDatagram(it) } }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        established = false
        runCatching { recvThread?.interrupt() }
        runCatching { keepaliveThread?.interrupt() }
        runCatching { socket?.close() }
        socket = null
        val h = wgHandle.getAndSet(0L)
        if (h > 0L) runCatching { Native.wgDestroy(h) }
    }

    companion object {
        private val lastTaiNs = java.util.concurrent.atomic.AtomicLong(0L)
    }
}

/**
 * Pure-Kotlin client RFC-793 userspace TCP/IPv4 stack operating directly over raw L3 IPv4 packets
 * (e.g. Cloudflare WARP WireGuard tunnel without root/admin privileges or kernel drivers).
 *
 * Implements 3-way handshake, MSS negotiation & clamping (<=1220 B for WireGuard MTU),
 * 32-bit wraparound-safe sequence arithmetic, partial-ACK trimming, out-of-order segment reassembly,
 * 3-duplicate-ACK fast retransmit, exponential-backoff RTO timer, and reliable FIN retransmission.
 */
class UserspaceTcpStack(
    val clientIpInt: Int,
    private val sendRawIp: (ByteArray) -> Boolean,
    private val mtu: Int = 1280,
) : AutoCloseable {
    private enum class TcpState { CLOSED, SYN_SENT, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT, LAST_ACK, TIME_WAIT }

    internal data class FlowKey(val localPort: Int, val remoteIp: Int, val remotePort: Int)

    private data class UnackedSeg(
        var seq: Long,
        val endSeq: Long,
        val flags: Int,
        var payload: ByteArray,
        var sentAtMs: Long,
        val firstSentMs: Long,
        var retries: Int,
    )

    private val closed = AtomicBoolean(false)
    private val connections = ConcurrentHashMap<FlowKey, UserspaceTcpSocket>()
    private val nextEphemeral = AtomicInteger(32768 + java.security.SecureRandom().nextInt(16000))
    private val localMss = (mtu - 40).coerceIn(536, 1220)
    val totalTxBytes = java.util.concurrent.atomic.AtomicLong(0L)
    val totalRxBytes = java.util.concurrent.atomic.AtomicLong(0L)
    val retransmits = java.util.concurrent.atomic.AtomicLong(0L)

    private val timerThread = Thread({
        while (!closed.get()) {
            try {
                Thread.sleep(25L)
            } catch (_: InterruptedException) {
                break
            }
            if (closed.get()) break
            val now = System.currentTimeMillis()
            val it = connections.entries.iterator()
            while (it.hasNext()) {
                val entry = it.next()
                val sock = entry.value
                val pkts = sock.pollRetransmit(now)
                for (p in pkts) {
                    emitIpPacket(p)
                }
                if (sock.isReapable(now)) {
                    connections.remove(entry.key, sock)
                }
            }
        }
    }, "freedom-utcp-timer").apply {
        isDaemon = true
        start()
    }

    private fun seqDiff(a: Long, b: Long): Int = (a.toInt() - b.toInt())
    private fun seqAdd(seq: Long, delta: Int): Long = (seq + delta.toLong()) and 0xFFFFFFFFL

    private fun emitIpPacket(pkt: ByteArray): Boolean {
        totalTxBytes.addAndGet(pkt.size.toLong())
        return sendRawIp(pkt)
    }

    private fun allocateLocalPort(dstIp: Int, dstPort: Int): Int {
        for (attempt in 0 until 2048) {
            val raw = nextEphemeral.getAndIncrement()
            val candidate = 32768 + ((raw and 0x7FFFFFFF) % 28000)
            val key = FlowKey(candidate, dstIp, dstPort)
            if (!connections.containsKey(key)) return candidate
        }
        throw IOException("Kullanılabilir yerel kullanıcı-alanı port kalmadı")
    }

    fun connect(remoteIpInt: Int, remotePort: Int, timeoutMs: Int = 5500): UserspaceTcpSocket {
        if (closed.get()) throw IOException("UserspaceTcpStack kapalı")
        if (remotePort !in 1..65535) throw IOException("Geçersiz hedef port: $remotePort")
        val localPort = allocateLocalPort(remoteIpInt, remotePort)
        val key = FlowKey(localPort, remoteIpInt, remotePort)
        val sock = UserspaceTcpSocket(key)
        connections[key] = sock
        return try {
            sock.connectInternal(timeoutMs)
            sock
        } catch (t: Throwable) {
            connections.remove(key, sock)
            sock.close()
            throw t
        }
    }

    fun tryConsumeInbound(pkt: ByteArray): Boolean {
        if (closed.get()) return false
        val ip = IpPackets.parseIpv4(pkt) ?: return false
        if (ip.proto != IpPackets.PROTO_TCP || ip.dstIp != clientIpInt) return false
        val seg = IpPackets.parseTcp(pkt, ip) ?: return false
        val key = FlowKey(seg.dstPort, ip.srcIp, seg.srcPort)
        val sock = connections[key] ?: return false
        totalRxBytes.addAndGet(pkt.size.toLong())
        sock.onSegment(pkt, ip, seg)
        return true
    }

    fun onInboundIpPacket(pkt: ByteArray) {
        tryConsumeInbound(pkt)
    }

    fun activeConnections(): Int = connections.size

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        runCatching { timerThread.interrupt() }
        for (sock in connections.values) {
            runCatching { sock.close() }
        }
        connections.clear()
    }

    inner class UserspaceTcpSocket internal constructor(
        private val key: FlowKey,
    ) : AutoCloseable {
        private val lock = java.util.concurrent.locks.ReentrantLock()
        private val rxCond = lock.newCondition()
        private val txCond = lock.newCondition()
        private val connectLatch = CountDownLatch(1)

        private var state = TcpState.CLOSED
        private var sndUna: Long = 0L
        private var sndNxt: Long = 0L
        private var sndWnd: Int = 32768
        private var lastAckedWnd: Int = 32768
        private var cwnd: Int = 16384
        private var rcvNxt: Long = 0L
        private var peerMss: Int = localMss
        private var peerFinSeq: Long? = null
        private var rxEof = false
        private var resetByPeer = false
        private var closedLocal = false
        private var finSent = false
        private var dupAcks = 0
        private var rtoMs = 180L
        private var srttMs = 90L
        private var lastAdvertisedWnd = RX_BUF_CAP
        private var closedAtMs = 0L

        private val rxChunks = kotlin.collections.ArrayDeque<ByteArray>()
        private var rxHeadOff = 0
        private var rxQueued = 0
        private val oooList = ArrayList<Pair<Long, ByteArray>>()
        private val unacked = ArrayList<UnackedSeg>()

        @Volatile var soTimeoutMs: Int = 30_000
        @Volatile var receivedAnyPayload: Boolean = false

        val inputStream: InputStream = object : InputStream() {
            override fun read(): Int {
                val one = ByteArray(1)
                val n = read(one, 0, 1)
                return if (n < 0) -1 else (one[0].toInt() and 0xFF)
            }

            override fun read(b: ByteArray, off: Int, len: Int): Int {
                if (len == 0) return 0
                return readBytes(b, off, len)
            }
        }

        val outputStream: OutputStream = object : OutputStream() {
            override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)
            override fun write(b: ByteArray, off: Int, len: Int) {
                if (len == 0) return
                writeBytes(b, off, len)
            }
            override fun flush() {}
        }

        private fun buildTcp(seq: Long, ack: Long, flags: Int, payload: ByteArray = ByteArray(0), mssOpt: Int = 0): ByteArray {
            val wnd = (RX_BUF_CAP - rxQueued).coerceIn(0, 65535)
            lastAdvertisedWnd = wnd
            return IpPackets.buildIpv4Tcp(
                srcIp = clientIpInt,
                dstIp = key.remoteIp,
                srcPort = key.localPort,
                dstPort = key.remotePort,
                seq = seq,
                ack = ack,
                flags = flags,
                window = wnd,
                payload = payload,
                mssOption = mssOpt,
            )
        }

        private fun parsePeerMss(raw: ByteArray, ihl: Int, dataOff: Int): Int? {
            if (dataOff <= 20 || ihl + dataOff > raw.size) return null
            var pos = ihl + 20
            val end = ihl + dataOff
            while (pos < end) {
                val kind = raw[pos].toInt() and 0xFF
                if (kind == 0) break
                if (kind == 1) { pos++; continue }
                if (pos + 1 >= end) break
                val len = raw[pos + 1].toInt() and 0xFF
                if (len < 2 || pos + len > end) break
                if (kind == 2 && len == 4 && pos + 4 <= end) {
                    return IpPackets.u16(raw, pos + 2)
                }
                pos += len
            }
            return null
        }

        internal fun connectInternal(timeoutMs: Int) {
            val iss = ((java.security.SecureRandom().nextInt() and 0x3FFFFFFF).toLong() + 1000L) and 0xFFFFFFFFL
            val synPkt: ByteArray
            val now = System.currentTimeMillis()
            lock.lock()
            try {
                state = TcpState.SYN_SENT
                sndUna = iss
                sndNxt = seqAdd(iss, 1)
                unacked.add(UnackedSeg(iss, sndNxt, IpPackets.TCP_SYN, ByteArray(0), now, now, 0))
                synPkt = buildTcp(iss, 0L, IpPackets.TCP_SYN, mssOpt = localMss)
            } finally {
                lock.unlock()
            }
            if (!emitIpPacket(synPkt)) {
                throw IOException("Kullanıcı-alanı SYN paketi gönderilemedi")
            }
            val signaled = connectLatch.await(timeoutMs.toLong(), TimeUnit.MILLISECONDS)
            lock.lock()
            try {
                if (!signaled || state != TcpState.ESTABLISHED) {
                    throw SocketTimeoutException("WARP TCP el sıkışması zaman aşımı (${IpPackets.ipToString(key.remoteIp)}:${key.remotePort})")
                }
            } finally {
                lock.unlock()
            }
        }

        private fun inflightBytes(): Int {
            var acc = 0
            for (u in unacked) acc += u.payload.size
            return acc
        }

        private fun appendRx(bytes: ByteArray) {
            if (bytes.isEmpty()) return
            rxChunks.addLast(bytes)
            rxQueued += bytes.size
            receivedAnyPayload = true
        }

        private fun drainOooLocked() {
            if (oooList.isEmpty()) return
            oooList.sortWith { a, b -> seqDiff(a.first, b.first) }
            val iter = oooList.iterator()
            while (iter.hasNext()) {
                val (startSeq, data) = iter.next()
                val overlap = seqDiff(rcvNxt, startSeq)
                if (overlap < 0) break
                iter.remove()
                if (overlap < data.size) {
                    val slice = if (overlap == 0) data else data.copyOfRange(overlap, data.size)
                    appendRx(slice)
                    rcvNxt = seqAdd(rcvNxt, slice.size)
                }
            }
        }

        internal fun onSegment(raw: ByteArray, ip: IpPackets.Ipv4Header, seg: IpPackets.TcpSegment) {
            val toSend = ArrayList<ByteArray>(2)
            var handshakeDone = false
            val now = System.currentTimeMillis()
            lock.lock()
            try {
                if ((seg.flags and IpPackets.TCP_RST) != 0) {
                    if (state == TcpState.SYN_SENT && (seg.flags and IpPackets.TCP_ACK) != 0 && seg.ack != sndNxt) {
                        return
                    }
                    resetByPeer = true
                    rxEof = true
                    state = TcpState.CLOSED
                    closedAtMs = now
                    unacked.clear()
                    rxCond.signalAll()
                    txCond.signalAll()
                    connectLatch.countDown()
                    return
                }
                if (state == TcpState.SYN_SENT) {
                    if ((seg.flags and (IpPackets.TCP_SYN or IpPackets.TCP_ACK)) == (IpPackets.TCP_SYN or IpPackets.TCP_ACK) &&
                        seg.ack == sndNxt
                    ) {
                        unacked.clear()
                        sndUna = seg.ack
                        rcvNxt = seqAdd(seg.seq, 1)
                        sndWnd = seg.window.coerceAtLeast(1024)
                        lastAckedWnd = seg.window
                        val offered = parsePeerMss(raw, ip.ihl, seg.dataOffset)
                        if (offered != null && offered in 536..localMss) {
                            peerMss = offered
                        }
                        state = TcpState.ESTABLISHED
                        toSend.add(buildTcp(sndNxt, rcvNxt, IpPackets.TCP_ACK))
                        handshakeDone = true
                    }
                    return
                }
                if (state == TcpState.CLOSED) return

                if ((seg.flags and IpPackets.TCP_ACK) != 0) {
                    val adv = seqDiff(seg.ack, sndUna)
                    if (adv > 0 && seqDiff(seg.ack, sndNxt) <= 0) {
                        val uIt = unacked.iterator()
                        while (uIt.hasNext()) {
                            val u = uIt.next()
                            if (seqDiff(seg.ack, u.endSeq) >= 0) {
                                if (u.retries == 0) {
                                    val sample = (now - u.firstSentMs).coerceIn(15L, 2000L)
                                    srttMs = (srttMs * 3L + sample) / 4L
                                    rtoMs = (srttMs * 2L).coerceIn(80L, 2500L)
                                }
                                uIt.remove()
                            } else if (u.payload.isNotEmpty() && seqDiff(seg.ack, u.seq) > 0 && seqDiff(seg.ack, u.endSeq) < 0) {
                                val ackedBytes = seqDiff(seg.ack, u.seq).coerceIn(0, u.payload.size)
                                if (ackedBytes > 0) {
                                    u.seq = seg.ack
                                    u.payload = u.payload.copyOfRange(ackedBytes, u.payload.size)
                                }
                                break
                            } else {
                                break
                            }
                        }
                        sndUna = seg.ack
                        dupAcks = 0
                        if (cwnd < 65536) cwnd = minOf(65536, cwnd + peerMss)
                        if (state == TcpState.FIN_WAIT_1 && finSent && unacked.none { (it.flags and IpPackets.TCP_FIN) != 0 }) {
                            state = TcpState.FIN_WAIT_2
                        } else if (state == TcpState.LAST_ACK && unacked.isEmpty()) {
                            state = TcpState.CLOSED
                            closedAtMs = now
                        }
                        txCond.signalAll()
                    } else if (adv == 0 && seg.payload.isEmpty() && (seg.flags and IpPackets.TCP_FIN) == 0 &&
                        unacked.isNotEmpty() && seg.window == lastAckedWnd
                    ) {
                        dupAcks++
                        if (dupAcks == 3) {
                            val oldest = unacked[0]
                            oldest.sentAtMs = now
                            oldest.retries++
                            retransmits.incrementAndGet()
                            cwnd = maxOf(peerMss * 2, cwnd / 2)
                            toSend.add(buildTcp(oldest.seq, rcvNxt, oldest.flags, oldest.payload))
                        }
                    }
                }
                lastAckedWnd = seg.window
                sndWnd = seg.window.coerceAtLeast(1024)

                var needAck = false
                if (seg.payload.isNotEmpty()) {
                    val rel = seqDiff(seg.seq, rcvNxt)
                    if (rel == 0) {
                        appendRx(seg.payload.copyOf())
                        rcvNxt = seqAdd(rcvNxt, seg.payload.size)
                        drainOooLocked()
                        needAck = true
                    } else if (rel < 0) {
                        needAck = true
                        val skip = -rel
                        if (skip < seg.payload.size) {
                            val tail = seg.payload.copyOfRange(skip, seg.payload.size)
                            appendRx(tail)
                            rcvNxt = seqAdd(rcvNxt, tail.size)
                            drainOooLocked()
                        }
                    } else if (rel < RX_BUF_CAP) {
                        needAck = true
                        if (oooList.size < 64 && oooList.none { it.first == seg.seq && it.second.size == seg.payload.size }) {
                            oooList.add(seg.seq to seg.payload.copyOf())
                        }
                    }
                }
                if ((seg.flags and IpPackets.TCP_FIN) != 0) {
                    val finAt = seqAdd(seg.seq, seg.payload.size)
                    if (peerFinSeq == null) peerFinSeq = finAt
                    needAck = true
                }
                val pf = peerFinSeq
                if (pf != null && seqDiff(rcvNxt, pf) >= 0) {
                    if (seqDiff(rcvNxt, pf) == 0) {
                        rcvNxt = seqAdd(rcvNxt, 1)
                        needAck = true
                    }
                    rxEof = true
                    state = when (state) {
                        TcpState.ESTABLISHED -> TcpState.CLOSE_WAIT
                        TcpState.FIN_WAIT_1, TcpState.FIN_WAIT_2 -> {
                            closedAtMs = now
                            TcpState.TIME_WAIT
                        }
                        else -> state
                    }
                }
                if (needAck) {
                    toSend.add(buildTcp(sndNxt, rcvNxt, IpPackets.TCP_ACK))
                }
                if (rxQueued > 0 || rxEof) {
                    rxCond.signalAll()
                }
            } finally {
                lock.unlock()
                for (p in toSend) emitIpPacket(p)
                if (handshakeDone) connectLatch.countDown()
            }
        }

        internal fun pollRetransmit(now: Long): List<ByteArray> {
            val out = ArrayList<ByteArray>(2)
            lock.lock()
            try {
                if (state == TcpState.TIME_WAIT && now - closedAtMs > 1200L) {
                    state = TcpState.CLOSED
                    return emptyList()
                }
                val oldest = unacked.firstOrNull() ?: return emptyList()
                if (now - oldest.sentAtMs < rtoMs) return emptyList()
                if (oldest.retries >= 8) {
                    resetByPeer = true
                    rxEof = true
                    state = TcpState.CLOSED
                    closedAtMs = now
                    unacked.clear()
                    rxCond.signalAll()
                    txCond.signalAll()
                    connectLatch.countDown()
                    return emptyList()
                }
                oldest.retries++
                oldest.sentAtMs = now
                rtoMs = minOf(2500L, (rtoMs * 3L) / 2L)
                retransmits.incrementAndGet()
                val mssOpt = if ((oldest.flags and IpPackets.TCP_SYN) != 0) localMss else 0
                out.add(buildTcp(oldest.seq, rcvNxt, oldest.flags, oldest.payload, mssOpt))
            } finally {
                lock.unlock()
            }
            return out
        }

        internal fun isReapable(now: Long): Boolean {
            lock.lock()
            return try {
                state == TcpState.CLOSED || (closedLocal && now - closedAtMs > 2000L)
            } finally {
                lock.unlock()
            }
        }

        private fun readBytes(dst: ByteArray, off: Int, len: Int): Int {
            var windowAckPkt: ByteArray? = null
            val copied: Int
            lock.lock()
            try {
                val deadlineNs = System.nanoTime() + soTimeoutMs.coerceAtLeast(1).toLong() * 1_000_000L
                while (rxQueued == 0) {
                    if (resetByPeer) throw IOException("Connection reset by peer")
                    if (rxEof || closedLocal || state == TcpState.CLOSED) return -1
                    val remNs = deadlineNs - System.nanoTime()
                    if (remNs <= 0L) throw SocketTimeoutException("WARP TCP okuma zaman aşımı")
                    rxCond.awaitNanos(remNs)
                }
                var done = 0
                while (done < len && rxChunks.isNotEmpty()) {
                    val head = rxChunks.first()
                    val avail = head.size - rxHeadOff
                    val take = minOf(len - done, avail)
                    System.arraycopy(head, rxHeadOff, dst, off + done, take)
                    done += take
                    rxQueued -= take
                    if (take == avail) {
                        rxChunks.removeFirst()
                        rxHeadOff = 0
                    } else {
                        rxHeadOff += take
                    }
                }
                copied = done
                val newWnd = (RX_BUF_CAP - rxQueued).coerceIn(0, 65535)
                if ((lastAdvertisedWnd < 4096 && newWnd >= 16384) || newWnd - lastAdvertisedWnd >= RX_BUF_CAP / 2) {
                    windowAckPkt = buildTcp(sndNxt, rcvNxt, IpPackets.TCP_ACK)
                }
            } finally {
                lock.unlock()
            }
            if (windowAckPkt != null) emitIpPacket(windowAckPkt)
            return copied
        }

        private fun writeBytes(src: ByteArray, off: Int, len: Int) {
            var pos = off
            val end = off + len
            while (pos < end) {
                val chunkLen = minOf(peerMss, end - pos)
                val chunk = src.copyOfRange(pos, pos + chunkLen)
                var pkt: ByteArray
                lock.lock()
                try {
                    val deadlineNs = System.nanoTime() + 15_000_000_000L
                    while ((state != TcpState.ESTABLISHED && state != TcpState.CLOSE_WAIT) ||
                        inflightBytes() >= minOf(cwnd, sndWnd).coerceAtLeast(peerMss)
                    ) {
                        if (resetByPeer || closedLocal || finSent || state == TcpState.CLOSED) {
                            throw IOException("Kullanıcı-alanı TCP soketi kapalı")
                        }
                        val remNs = deadlineNs - System.nanoTime()
                        if (remNs <= 0L) throw SocketTimeoutException("WARP TCP yazma zaman aşımı")
                        txCond.awaitNanos(remNs)
                    }
                    if (resetByPeer || closedLocal || finSent || state == TcpState.CLOSED) {
                        throw IOException("Kullanıcı-alanı TCP soketi kapalı")
                    }
                    val now = System.currentTimeMillis()
                    val seq = sndNxt
                    val endSeq = seqAdd(seq, chunk.size)
                    sndNxt = endSeq
                    val flags = IpPackets.TCP_PSH or IpPackets.TCP_ACK
                    unacked.add(UnackedSeg(seq, endSeq, flags, chunk, now, now, 0))
                    pkt = buildTcp(seq, rcvNxt, flags, chunk)
                } finally {
                    lock.unlock()
                }
                if (!emitIpPacket(pkt)) throw IOException("WARP paket gönderilemedi")
                pos += chunkLen
            }
        }

        fun shutdownOutput() {
            var finPkt: ByteArray? = null
            lock.lock()
            try {
                if (!finSent && !closedLocal && (state == TcpState.ESTABLISHED || state == TcpState.CLOSE_WAIT)) {
                    finSent = true
                    val now = System.currentTimeMillis()
                    val seq = sndNxt
                    val endSeq = seqAdd(seq, 1)
                    sndNxt = endSeq
                    val flags = IpPackets.TCP_FIN or IpPackets.TCP_ACK
                    unacked.add(UnackedSeg(seq, endSeq, flags, ByteArray(0), now, now, 0))
                    state = if (state == TcpState.CLOSE_WAIT) TcpState.LAST_ACK else TcpState.FIN_WAIT_1
                    finPkt = buildTcp(seq, rcvNxt, flags)
                }
            } finally {
                lock.unlock()
            }
            if (finPkt != null) emitIpPacket(finPkt)
        }

        override fun close() {
            var pkt: ByteArray? = null
            lock.lock()
            try {
                if (closedLocal) return
                closedLocal = true
                closedAtMs = System.currentTimeMillis()
                if (!finSent && (state == TcpState.ESTABLISHED || state == TcpState.CLOSE_WAIT)) {
                    finSent = true
                    val seq = sndNxt
                    val endSeq = seqAdd(seq, 1)
                    sndNxt = endSeq
                    val flags = IpPackets.TCP_FIN or IpPackets.TCP_ACK
                    unacked.add(UnackedSeg(seq, endSeq, flags, ByteArray(0), closedAtMs, closedAtMs, 0))
                    pkt = buildTcp(seq, rcvNxt, flags)
                    state = if (state == TcpState.CLOSE_WAIT) TcpState.LAST_ACK else TcpState.FIN_WAIT_1
                } else if (state == TcpState.SYN_SENT) {
                    pkt = buildTcp(sndNxt, rcvNxt, IpPackets.TCP_RST)
                    state = TcpState.CLOSED
                }
                rxEof = true
                rxCond.signalAll()
                txCond.signalAll()
                connectLatch.countDown()
            } finally {
                lock.unlock()
            }
            if (pkt != null) emitIpPacket(pkt)
        }
    }

    companion object {
        private const val RX_BUF_CAP = 65535
    }
}

/**
 * Freedom Network User-Mode TUN -> Protected Socket Bridge (`tun2socks` + Built-in Auto-WARP WireGuard +
 * Happy Eyeballs DoH3 + Privacy/Tracker Shield + Strict Kill Switch + Universal TCP/TLS/ECH Desync +
 * Low-Latency UDP NAT).
 *
 * Bridges raw IPv4/IPv6 packets from the TUN descriptor (`0.0.0.0/0` + `::/0`) to real outbound
 * encrypted WireGuard WARP or `VpnService.protect()`ed TCP/UDP sockets:
 * 1. **Built-in Zero-Config Public IP Masking**: Automatically provisions and connects a pure-Rust
 *    WireGuard WARP tunnel (with Tor SOCKS5 `:9050` auto-detection and Direct DPI fallback) unless an
 *    explicit Exit Relay is specified.
 * 2. **Encrypted DNS & Tracker Shield (UDP/TCP 53)**: Resolves via parallel Happy Eyeballs
 *    RFC 8484 DoH3/DoH (`DohClient`), strips ISP DNS poisoning & DNS-rebinding private answers,
 *    suppresses unbridged `AAAA` probes, and blocks telemetry/ad/geo-beacon domains (`blockTrackers`).
 * 3. **Universal TCP + TLS 1.3 / ECH / PQ Desync + Device Identity Spoofing**: Fragments `SNI`/`ECH`
 *    across TLS records via Rust+SIMD `desyncPacket` in direct DPI mode and rewrites plaintext HTTP
 *    device headers to a non-existent [DevicePersona] (`iPhone 19 Beta`, `Android 19 Quantum`).
 * 4. **Universal UDP NAT & Leak Protection**: Routes/NATs UDP streams while blocking STUN/WebRTC/mDNS/SSDP leaks.
 */
class TunBridge(
    private val session: DiagnosticSession,
    private val tunInput: InputStream,
    private val tunOutput: OutputStream,
    private val protectSocket: (Socket) -> Boolean = { true },
    private val protectDatagram: (DatagramSocket) -> Boolean = { true },
    private val dohClient: DohClient? = null,
    private val dohEndpoints: List<String> = DEFAULT_DOH_ENDPOINTS,
    private val upstreamDnsServers: List<String> = DEFAULT_DNS_SERVERS,
    private val desyncConfig: DesyncConfig = DesyncConfig(
        mode = DesyncMode.REALITY_VISION,
        fakeTtl = 5,
        splitPos = 2,
        dropRst = true,
    ),
    private val blockQuic: Boolean = true,
    private val strictKillSwitch: Boolean = false,
    private val blockTrackers: Boolean = false,
    private val hardenStunLeaks: Boolean = false,
    private val logger: ((String, String) -> Unit)? = null,
    private val exitRelayUri: String = "",
    private val autoWarp: Boolean = false,
    private val initialWarpIdentity: WarpIdentity? = null,
    private val devicePersona: DevicePersona = DevicePersona.OFF,
    private val suppressIpv6Dns: Boolean = true,
    private val onWarpIdentityReady: ((WarpIdentity) -> Unit)? = null,
    private val onRouteChanged: ((String, Boolean) -> Unit)? = null,
) : AutoCloseable {
    private fun log(tag: String, msg: String) {
        logger?.invoke(tag, msg)
    }

    private data class FlowKey(val srcIp: Int, val srcPort: Int, val dstIp: Int, val dstPort: Int)
    private data class WarpFlowKey(val proto: Int, val localPort: Int, val remoteIp: Int, val remotePort: Int)

    @Volatile var activeBlockQuic: Boolean = blockQuic
        private set
    @Volatile var activeStrictKillSwitch: Boolean = strictKillSwitch
        private set
    @Volatile var activeBlockTrackers: Boolean = blockTrackers
        private set
    @Volatile var activeHardenStunLeaks: Boolean = hardenStunLeaks
        private set
    @Volatile private var currentDevicePersona: DevicePersona = devicePersona
    @Volatile private var activeExitRelay: ExitRelayConfig? = ExitRelayConfig.parse(exitRelayUri)
    private val exitRelay: ExitRelayConfig? get() = activeExitRelay
    @Volatile private var warpTunnel: WarpTunnel? = null
    @Volatile private var probeStack: UserspaceTcpStack? = null
    @Volatile private var warpClientIpInt: Int = 0
    private val tunClientIpInt: Int = IpPackets.parseIpLiteral(VPN_CLIENT_IP) ?: 0x0AD7AD01
    private val warpBootstrapping = AtomicBoolean(false)
    @Volatile private var routeMasked: Boolean = activeExitRelay != null
    @Volatile private var routeLabel: String = activeExitRelay?.label()
        ?: if (autoWarp) "WARP WireGuard Bağlanıyor..." else "Doğrudan (Yerel DPI)"

    private val running = AtomicBoolean(false)
    private val writeLock = Any()
    private val ioPool: ExecutorService = Executors.newCachedThreadPool { r ->
        Thread(r, "freedom-tun-io").apply { isDaemon = true }
    }
    private var readerThread: Thread? = null
    private val tcpTable = ConcurrentHashMap<FlowKey, TcpFlow>()
    private val udpTable = ConcurrentHashMap<FlowKey, UdpFlow>()
    private val warpFlows = ConcurrentHashMap<WarpFlowKey, Long>()
    private val warpIcmpPending = ConcurrentHashMap<Int, Long>()
    private val dnsIpToHost = ConcurrentHashMap<Int, String>()
    private val virtualDnsIp: Int = IpPackets.parseIpLiteral(VPN_DNS_IP) ?: 0x0AD7AD02
    private val dnsCache = ConcurrentHashMap<String, Triple<Long, Long, ByteArray>>()
    private val dnsRefreshInFlight = ConcurrentHashMap.newKeySet<String>()
    @Volatile private var preferredDoh = 0

    val isExitRelayActive: Boolean get() = activeExitRelay != null
    val isWarpActive: Boolean get() = warpTunnel?.established == true
    val isIpMasked: Boolean get() = routeMasked || isWarpActive || isExitRelayActive
    val activeExitRelayLabel: String get() = routeLabel
    val activeDevicePersona: DevicePersona get() = currentDevicePersona

    val tcpFlows = AtomicInteger(0)
    val udpFlows = AtomicInteger(0)
    val dnsQueries = AtomicInteger(0)
    val dohResolved = AtomicInteger(0)
    val desyncedFlows = AtomicInteger(0)
    val visionSplicedFlows = AtomicInteger(0)
    val roamingRebinds = AtomicInteger(0)
    val poisonedDnsBlocked = AtomicInteger(0)
    val quicFallbacks = AtomicInteger(0)
    val tlsRecordFragmented = AtomicInteger(0)
    val dnsCacheHits = AtomicInteger(0)
    val warpDnsFastHits = AtomicInteger(0)
    val paramsStripped = AtomicInteger(0)
    val ipv6Rejected = AtomicInteger(0)
    val aaaaSuppressed = AtomicInteger(0)
    val trackersBlocked = AtomicInteger(0)
    val leaksBlocked = AtomicInteger(0)
    val httpHeadersSpoofed = AtomicInteger(0)
    val warpPacketsOut = java.util.concurrent.atomic.AtomicLong(0)
    val warpPacketsIn = java.util.concurrent.atomic.AtomicLong(0)
    val bytesUp = java.util.concurrent.atomic.AtomicLong(0)
    val bytesDown = java.util.concurrent.atomic.AtomicLong(0)

    fun updateSettings(
        blockQuic: Boolean? = null,
        strictKillSwitch: Boolean? = null,
        blockTrackers: Boolean? = null,
        hardenStunLeaks: Boolean? = null,
        devicePersona: DevicePersona? = null,
        exitRelayUri: String? = null,
    ) {
        blockQuic?.let { activeBlockQuic = it }
        strictKillSwitch?.let { activeStrictKillSwitch = it }
        blockTrackers?.let { activeBlockTrackers = it }
        hardenStunLeaks?.let { activeHardenStunLeaks = it }
        devicePersona?.let { currentDevicePersona = it }
        if (exitRelayUri != null) {
            val parsed = ExitRelayConfig.parse(exitRelayUri)
            activeExitRelay = parsed
            if (parsed != null) {
                routeMasked = true
                routeLabel = parsed.label()
                onRouteChanged?.invoke(routeLabel, true)
            } else if (isWarpActive) {
                routeMasked = true
                val ep = warpTunnel?.activeEndpoint
                routeLabel = "WARP WireGuard (${ep?.hostString ?: ""}:${ep?.port ?: 2408})"
                onRouteChanged?.invoke(routeLabel, true)
            } else if (autoWarp && !warpBootstrapping.get() && running.get()) {
                warpBootstrapping.set(true)
                routeMasked = false
                routeLabel = "WARP WireGuard Bağlanıyor..."
                onRouteChanged?.invoke(routeLabel, false)
                ioPool.execute { initAutoRoute() }
            } else {
                routeMasked = false
                routeLabel = "Doğrudan DPI + DoH3 (IP Maskesiz)"
                onRouteChanged?.invoke(routeLabel, false)
            }
        }
        log(
            "TunBridge",
            "Canlı ayar güncellendi (blockQuic=$activeBlockQuic, killSwitch=$activeStrictKillSwitch, trackers=$activeBlockTrackers, stunShield=$activeHardenStunLeaks, persona=${currentDevicePersona.id})",
        )
    }

    /**
     * Handles seamless Wi-Fi <-> Mobile Data (LTE/5G) roaming by refreshing ephemeral UDP NAT
     * bindings and re-protecting active sockets + WireGuard UDP socket without tearing down TUN.
     */
    fun rebindActiveSessions() {
        roamingRebinds.incrementAndGet()
        warpTunnel?.reprotect()
        for (u in udpTable.values) {
            u.socket?.let { runCatching { protectDatagram(it) } }
        }
        for (t in tcpTable.values) {
            t.upstreamSocket?.let { runCatching { protectSocket(it) } }
        }
    }

    private fun isLocalPortOpen(host: String, port: Int, timeoutMs: Int = 500): Boolean = runCatching {
        Socket().use { s ->
            s.connect(InetSocketAddress(InetAddress.getByName(host), port), timeoutMs)
        }
        true
    }.getOrDefault(false)

    internal fun recordWarpOutbound(natOut: ByteArray) {
        val natIp = IpPackets.parseIpv4(natOut) ?: return
        val nowMs = System.currentTimeMillis()
        when (natIp.proto) {
            IpPackets.PROTO_TCP -> IpPackets.parseTcp(natOut, natIp)?.let { seg ->
                if (warpFlows.size > 2048) {
                    warpFlows.entries.removeIf { nowMs - it.value > 120_000L }
                }
                warpFlows[WarpFlowKey(IpPackets.PROTO_TCP, seg.srcPort, natIp.dstIp, seg.dstPort)] = nowMs
            }
            IpPackets.PROTO_UDP -> IpPackets.parseUdp(natOut, natIp)?.let { udp ->
                if (warpFlows.size > 2048) {
                    warpFlows.entries.removeIf { nowMs - it.value > 120_000L }
                }
                warpFlows[WarpFlowKey(IpPackets.PROTO_UDP, udp.srcPort, natIp.dstIp, udp.dstPort)] = nowMs
            }
            IpPackets.PROTO_ICMP -> if (natIp.ihl + 8 <= natOut.size && (natOut[natIp.ihl].toInt() and 0xFF) == 8) {
                val icmpId = IpPackets.u16(natOut, natIp.ihl + 4)
                if (warpIcmpPending.size > 512) {
                    warpIcmpPending.entries.removeIf { nowMs - it.value > 30_000L }
                }
                warpIcmpPending[icmpId] = nowMs
            }
        }
    }

    internal fun isAllowedWarpInbound(dec: ByteArray): Boolean {
        val ip = IpPackets.parseIpv4(dec) ?: return false
        val nowMs = System.currentTimeMillis()
        return when (ip.proto) {
            IpPackets.PROTO_TCP -> {
                val seg = IpPackets.parseTcp(dec, ip) ?: return false
                val k = WarpFlowKey(IpPackets.PROTO_TCP, seg.dstPort, ip.srcIp, seg.srcPort)
                if (warpFlows.containsKey(k)) {
                    warpFlows[k] = nowMs
                    true
                } else {
                    false
                }
            }
            IpPackets.PROTO_UDP -> {
                val udp = IpPackets.parseUdp(dec, ip) ?: return false
                val k = WarpFlowKey(IpPackets.PROTO_UDP, udp.dstPort, ip.srcIp, udp.srcPort)
                if (warpFlows.containsKey(k)) {
                    warpFlows[k] = nowMs
                    true
                } else {
                    false
                }
            }
            IpPackets.PROTO_ICMP -> {
                if (dec.size < ip.ihl + 8) return false
                val icmpType = dec[ip.ihl].toInt() and 0xFF
                if (icmpType == 0) {
                    val icmpId = IpPackets.u16(dec, ip.ihl + 4)
                    warpIcmpPending.containsKey(icmpId)
                } else if ((icmpType == 3 || icmpType == 11) && dec.size >= ip.ihl + 8 + 28) {
                    val inner = dec.copyOfRange(ip.ihl + 8, dec.size)
                    val innerIp = IpPackets.parseIpv4(inner) ?: return false
                    if (inner.size < innerIp.ihl + 4) return false
                    val innerSrcPort = IpPackets.u16(inner, innerIp.ihl)
                    val innerDstPort = IpPackets.u16(inner, innerIp.ihl + 2)
                    warpFlows.containsKey(WarpFlowKey(innerIp.proto, innerSrcPort, innerIp.dstIp, innerDstPort))
                } else {
                    false
                }
            }
            else -> false
        }
    }

    private fun resolveIpv4OverDoh(host: String): Int? {
        IpPackets.parseIpLiteral(host)?.let { return it }
        dnsIpToHost.entries.firstOrNull { it.value.equals(host, ignoreCase = true) }?.key?.let { return it }
        val q = Doh.query(host) ?: return null
        val client = dohClient ?: return null
        val eps = dohEndpoints.filter(Doh::validEndpoint)
        for (ep in eps) {
            val resp = runCatching { client.post(ep, q, 2500) }.getOrNull() ?: continue
            val body = resp.body
            if (resp.transport == 1 && body != null && body.size >= 12 && !IpPackets.containsPoisonedDns(body)) {
                val addrs = IpPackets.dnsAnswerAddresses(body)
                val v4 = addrs?.firstOrNull { it.size == 4 }
                if (v4 != null) {
                    val ipInt = ((v4[0].toInt() and 0xFF) shl 24) or
                        ((v4[1].toInt() and 0xFF) shl 16) or
                        ((v4[2].toInt() and 0xFF) shl 8) or
                        (v4[3].toInt() and 0xFF)
                    dnsIpToHost[ipInt] = host
                    return ipInt
                }
            }
        }
        return null
    }

    fun probeHttpGetOverWarp(
        host: String,
        port: Int = 443,
        path: String = "/cdn-cgi/trace",
        timeoutMs: Int = 4500,
    ): String? {
        val stack = probeStack ?: return null
        if (!isWarpActive) return null
        val targetIpInt = resolveIpv4OverDoh(host) ?: return null
        val uSock = stack.connect(targetIpInt, port, timeoutMs)
        return try {
            uSock.soTimeoutMs = timeoutMs
            val targetAddr = InetAddress.getByAddress(IpPackets.ipToBytes(targetIpInt))
            val delegate = object : Socket() {
                override fun getInputStream(): InputStream = uSock.inputStream
                override fun getOutputStream(): OutputStream = uSock.outputStream
                override fun getInetAddress(): InetAddress = targetAddr
                override fun getPort(): Int = port
                override fun getRemoteSocketAddress(): java.net.SocketAddress = InetSocketAddress(targetAddr, port)
                override fun isConnected(): Boolean = true
                override fun isClosed(): Boolean = false
                override fun setSoTimeout(timeout: Int) { uSock.soTimeoutMs = timeout }
                override fun getSoTimeout(): Int = uSock.soTimeoutMs
                override fun close() = uSock.close()
            }
            val ssl = (SSLSocketFactory.getDefault() as SSLSocketFactory)
                .createSocket(delegate, host, port, true) as SSLSocket
            ssl.use { s ->
                val params = s.sslParameters
                params.endpointIdentificationAlgorithm = "HTTPS"
                s.sslParameters = params
                s.soTimeout = timeoutMs
                s.startHandshake()
                val req = "GET $path HTTP/1.1\r\nHost: $host\r\nUser-Agent: FreedomNetwork/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
                s.outputStream.write(req.toByteArray(Charsets.US_ASCII))
                s.outputStream.flush()
                val bis = java.io.BufferedInputStream(s.inputStream)
                val statusLine = IpPackets.readBoundedHttpLine(bis)
                val code = statusLine.split(' ').getOrNull(1)?.toIntOrNull() ?: 0
                if (code !in 200..299) return null
                val headers = HashMap<String, String>()
                while (true) {
                    val line = IpPackets.readBoundedHttpLine(bis)
                    if (line.isEmpty()) break
                    val idx = line.indexOf(':')
                    if (idx > 0) headers[line.substring(0, idx).trim().lowercase(java.util.Locale.US)] = line.substring(idx + 1).trim()
                }
                val bodyBytes = if (headers["transfer-encoding"].orEmpty().contains("chunked", ignoreCase = true)) {
                    val acc = ByteArrayOutputStream()
                    while (true) {
                        val sz = IpPackets.readBoundedHttpLine(bis).substringBefore(';').trim().toIntOrNull(16) ?: break
                        if (sz == 0) break
                        if (acc.size() + sz > 131_072) break
                        acc.write(readExactBytes(bis, sz))
                        IpPackets.readBoundedHttpLine(bis)
                    }
                    acc.toByteArray()
                } else {
                    val cl = headers["content-length"]?.toIntOrNull()
                    if (cl != null && cl in 0..131_072) {
                        readExactBytes(bis, cl)
                    } else {
                        val acc = ByteArrayOutputStream()
                        val buf = ByteArray(4096)
                        while (acc.size() < 131_072) {
                            val k = bis.read(buf)
                            if (k <= 0) break
                            acc.write(buf, 0, k)
                        }
                        acc.toByteArray()
                    }
                }
                String(bodyBytes, Charsets.UTF_8)
            }
        } finally {
            runCatching { uSock.close() }
        }
    }

    private fun onWarpInbound(dec: ByteArray) {
        if (dec.size < 20 || ((dec[0].toInt() ushr 4) and 0x0F) != 4) return
        if (probeStack?.tryConsumeInbound(dec) == true) {
            warpPacketsIn.incrementAndGet()
            return
        }
        if (!isAllowedWarpInbound(dec)) {
            leaksBlocked.incrementAndGet()
            return
        }
        val nat = IpPackets.rewriteIpv4Nat(dec, newDstIp = tunClientIpInt) ?: return
        warpPacketsIn.incrementAndGet()
        bytesDown.addAndGet(nat.size.toLong())
        writeTun(nat)
    }

    private fun initAutoRoute() {
        try {
            var id = initialWarpIdentity?.takeIf { it.isValid() }
            var freshRegistered = false
            if (id == null) {
                id = WarpProvisioner.register(protectSocket, logger)
                freshRegistered = id != null
                if (id != null) onWarpIdentityReady?.invoke(id)
            }
            if (id != null && running.get()) {
                val wt = WarpTunnel(id, protectDatagram, logger)
                if (wt.connect(3200)) {
                    val cIp = id.clientIpInt() ?: 0
                    warpClientIpInt = cIp
                    runCatching { probeStack?.close() }
                    probeStack = if (cIp != 0) UserspaceTcpStack(cIp, { raw -> wt.sendIpPacket(raw) }) else null
                    warpTunnel = wt
                    routeMasked = true
                    routeLabel = "WARP WireGuard (${wt.activeEndpoint?.hostString ?: id.endpointHost}:${wt.activeEndpoint?.port ?: id.endpointPort})"
                    wt.startLoops { dec -> onWarpInbound(dec) }
                    warpBootstrapping.set(false)
                    log("TunBridge", "Otomatik rota seçildi: $routeLabel")
                    onRouteChanged?.invoke(routeLabel, true)
                    return
                }
                wt.close()
                if (!freshRegistered && running.get()) {
                    val refreshed = WarpProvisioner.register(protectSocket, logger)
                    if (refreshed != null) {
                        onWarpIdentityReady?.invoke(refreshed)
                        val wt2 = WarpTunnel(refreshed, protectDatagram, logger)
                        if (wt2.connect(3200)) {
                            val cIp = refreshed.clientIpInt() ?: 0
                            warpClientIpInt = cIp
                            runCatching { probeStack?.close() }
                            probeStack = if (cIp != 0) UserspaceTcpStack(cIp, { raw -> wt2.sendIpPacket(raw) }) else null
                            warpTunnel = wt2
                            routeMasked = true
                            routeLabel = "WARP WireGuard (${wt2.activeEndpoint?.hostString ?: refreshed.endpointHost}:${wt2.activeEndpoint?.port ?: refreshed.endpointPort})"
                            wt2.startLoops { dec -> onWarpInbound(dec) }
                            warpBootstrapping.set(false)
                            log("TunBridge", "Otomatik rota seçildi (yenilenen anahtar): $routeLabel")
                            onRouteChanged?.invoke(routeLabel, true)
                            return
                        }
                        wt2.close()
                    }
                }
            }
            if (running.get() && isLocalPortOpen("127.0.0.1", 9050, 450)) {
                activeExitRelay = ExitRelayConfig("socks5", "127.0.0.1", 9050)
                routeMasked = true
                routeLabel = "Tor / Orbot (127.0.0.1:9050)"
                warpBootstrapping.set(false)
                log("TunBridge", "WARP UDP engelli; otomatik Tor/Orbot yedeğine geçildi")
                onRouteChanged?.invoke(routeLabel, true)
                return
            }
        } catch (t: Throwable) {
            log("TunBridge", "Otomatik WARP başlatma hatası: ${t.message}")
        } finally {
            warpBootstrapping.set(false)
        }
        routeMasked = false
        routeLabel = "Doğrudan DPI + DoH3 (IP Maskesiz)"
        log("TunBridge", "Otomatik yedek rota: $routeLabel")
        onRouteChanged?.invoke(routeLabel, false)
    }

    fun start() {
        if (!running.compareAndSet(false, true)) return
        log(
            "TunBridge",
            "Freedom Network TunBridge başlatıldı (DoH=${dohEndpoints.size}, autoWarp=$autoWarp, relay=${activeExitRelayLabel}, persona=${currentDevicePersona.id}, killSwitch=$activeStrictKillSwitch, trackers=$activeBlockTrackers, stunShield=$activeHardenStunLeaks)",
        )
        if (activeExitRelay == null && autoWarp) {
            warpBootstrapping.set(true)
            ioPool.execute { initAutoRoute() }
        }
        readerThread = Thread({ readLoop() }, "freedom-tun-reader").apply {
            isDaemon = true
            start()
        }
    }

    private fun writeTun(pkt: ByteArray) {
        if (!running.get()) return
        synchronized(writeLock) {
            try {
                tunOutput.write(pkt)
                tunOutput.flush()
            } catch (_: Throwable) {
            }
        }
    }

    private fun readLoop() {
        val buf = ByteArray(32767)
        while (running.get()) {
            val n = try {
                tunInput.read(buf)
            } catch (_: Throwable) {
                break
            }
            if (n <= 0) {
                if (n < 0) break
                // Non-blocking TUN descriptor returned EAGAIN: yield instead of spinning.
                try { Thread.sleep(2) } catch (_: InterruptedException) { break }
                continue
            }
            var off = 0
            while (off + 20 <= n && ((buf[off].toInt() ushr 4) and 0x0F) == 4) {
                val pktLen = IpPackets.u16(buf, off + 2)
                if (pktLen < 20 || off + pktLen > n) break
                val pkt = buf.copyOfRange(off, off + pktLen)
                try {
                    dispatchPacket(pkt)
                } catch (_: Throwable) {
                    if (!running.get()) break
                }
                off += pktLen
            }
            if (off == 0) {
                try {
                    dispatchPacket(buf.copyOf(n))
                } catch (_: Throwable) {
                    if (!running.get()) break
                }
            }
        }
    }

    private fun readExactBytes(input: InputStream, n: Int): ByteArray {
        val out = ByteArray(n)
        var got = 0
        while (got < n) {
            val k = input.read(out, got, n - got)
            if (k < 0) throw IOException("EOF")
            got += k
        }
        return out
    }

    private fun readHttpHeaderLine(input: InputStream): String = IpPackets.readBoundedHttpLine(input, 8192)

    private fun openExitRelayTunnel(
        relay: ExitRelayConfig,
        dstHostOrIp: String,
        dstPort: Int,
        timeoutMs: Int = 5500,
    ): Socket {
        val raw = Socket()
        try {
            raw.bind(null)
            if (!relay.isLoopback()) {
                protectSocket(raw)
            }
            raw.tcpNoDelay = true
            runCatching { raw.trafficClass = 0x10 }
            raw.connect(InetSocketAddress(InetAddress.getByName(relay.host), relay.port), timeoutMs)
            raw.soTimeout = timeoutMs

            val connSock: Socket = if (relay.scheme == "https") {
                val sslFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
                val ssl = sslFactory.createSocket(raw, relay.host, relay.port, true) as SSLSocket
                val params = ssl.sslParameters
                params.endpointIdentificationAlgorithm = "HTTPS"
                ssl.sslParameters = params
                ssl.startHandshake()
                ssl
            } else {
                raw
            }

            val input = connSock.getInputStream()
            val out = connSock.getOutputStream()

            if (relay.scheme == "socks5") {
                val hasAuth = relay.username.isNotEmpty() || relay.password.isNotEmpty()
                val greet = if (hasAuth) byteArrayOf(0x05, 0x02, 0x00, 0x02) else byteArrayOf(0x05, 0x01, 0x00)
                out.write(greet)
                out.flush()
                val choice = readExactBytes(input, 2)
                if (choice[0].toInt() != 0x05) throw IOException("SOCKS5 bad version")
                val method = choice[1].toInt() and 0xFF
                if (method == 0x02) {
                    val u = relay.username.toByteArray(Charsets.UTF_8).take(255).toByteArray()
                    val p = relay.password.toByteArray(Charsets.UTF_8).take(255).toByteArray()
                    val auth = ByteArray(3 + u.size + p.size)
                    auth[0] = 0x01
                    auth[1] = u.size.toByte()
                    System.arraycopy(u, 0, auth, 2, u.size)
                    auth[2 + u.size] = p.size.toByte()
                    System.arraycopy(p, 0, auth, 3 + u.size, p.size)
                    out.write(auth)
                    out.flush()
                    val authReply = readExactBytes(input, 2)
                    if (authReply[1].toInt() != 0x00) throw IOException("SOCKS5 auth rejected")
                } else if (method != 0x00) {
                    throw IOException("SOCKS5 unsupported auth method: $method")
                }

                val ipv4 = IpPackets.parseIpLiteral(dstHostOrIp)
                val req = if (ipv4 != null) {
                    val ipB = IpPackets.ipToBytes(ipv4)
                    byteArrayOf(
                        0x05, 0x01, 0x00, 0x01,
                        ipB[0], ipB[1], ipB[2], ipB[3],
                        ((dstPort ushr 8) and 0xFF).toByte(),
                        (dstPort and 0xFF).toByte(),
                    )
                } else {
                    val hostB = dstHostOrIp.toByteArray(Charsets.UTF_8)
                    if (hostB.isEmpty() || hostB.size > 255) throw IOException("SOCKS5 bad host")
                    ByteArray(7 + hostB.size).also { b ->
                        b[0] = 0x05; b[1] = 0x01; b[2] = 0x00; b[3] = 0x03
                        b[4] = hostB.size.toByte()
                        System.arraycopy(hostB, 0, b, 5, hostB.size)
                        b[5 + hostB.size] = ((dstPort ushr 8) and 0xFF).toByte()
                        b[6 + hostB.size] = (dstPort and 0xFF).toByte()
                    }
                }
                out.write(req)
                out.flush()
                val hdr = readExactBytes(input, 4)
                if (hdr[0].toInt() != 0x05 || hdr[1].toInt() != 0x00) {
                    throw IOException("SOCKS5 CONNECT failed: rep=${hdr[1].toInt() and 0xFF}")
                }
                when (hdr[3].toInt() and 0xFF) {
                    0x01 -> readExactBytes(input, 6)
                    0x03 -> {
                        val dLen = readExactBytes(input, 1)[0].toInt() and 0xFF
                        readExactBytes(input, dLen + 2)
                    }
                    0x04 -> readExactBytes(input, 18)
                    else -> throw IOException("SOCKS5 unknown ATYP")
                }
            } else {
                val target = "$dstHostOrIp:$dstPort"
                val sb = StringBuilder()
                sb.append("CONNECT ").append(target).append(" HTTP/1.1\r\n")
                sb.append("Host: ").append(target).append("\r\n")
                if (relay.username.isNotEmpty() || relay.password.isNotEmpty()) {
                    val creds = "${relay.username}:${relay.password}".toByteArray(Charsets.UTF_8)
                    val b64 = java.util.Base64.getEncoder().encodeToString(creds)
                    sb.append("Proxy-Authorization: Basic ").append(b64).append("\r\n")
                }
                sb.append("\r\n")
                out.write(sb.toString().toByteArray(Charsets.US_ASCII))
                out.flush()
                val statusLine = readHttpHeaderLine(input)
                val code = statusLine.split(' ').getOrNull(1)?.toIntOrNull() ?: 0
                if (code !in 200..299) {
                    throw IOException("Proxy CONNECT failed: $statusLine")
                }
                while (readHttpHeaderLine(input).isNotEmpty()) { /* drain proxy response headers */ }
            }
            connSock.soTimeout = 90_000
            return connSock
        } catch (t: Throwable) {
            runCatching { raw.close() }
            throw t
        }
    }

    private fun postDohViaRelay(
        relay: ExitRelayConfig,
        url: String,
        wireQuery: ByteArray,
        timeoutMs: Int,
    ): DohResponse? {
        val start = System.nanoTime()
        fun rtt() = (System.nanoTime() - start) / 1000
        val uri = runCatching { java.net.URI(url) }.getOrNull() ?: return null
        val host = uri.host?.trim('[', ']') ?: return null
        val port = if (uri.port > 0) uri.port else 443
        val path = (uri.rawPath ?: "/dns-query").ifEmpty { "/dns-query" }
        var tunnel: Socket? = null
        var ssl: SSLSocket? = null
        return try {
            tunnel = openExitRelayTunnel(relay, host, port, timeoutMs)
            val sslFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
            ssl = sslFactory.createSocket(tunnel, host, port, true) as SSLSocket
            val params = ssl.sslParameters
            params.endpointIdentificationAlgorithm = "HTTPS"
            ssl.sslParameters = params
            ssl.soTimeout = timeoutMs
            ssl.startHandshake()

            val hostHeader = if (host.contains(':')) "[$host]" else host
            val head = "POST $path HTTP/1.1\r\nHost: $hostHeader\r\n" +
                "Content-Type: application/dns-message\r\nAccept: application/dns-message\r\n" +
                "Content-Length: ${wireQuery.size}\r\nConnection: close\r\n\r\n"
            val out = ssl.outputStream
            out.write(head.toByteArray(Charsets.US_ASCII))
            out.write(wireQuery)
            out.flush()

            val input = java.io.BufferedInputStream(ssl.inputStream)
            val statusLine = readHttpHeaderLine(input)
            val status = statusLine.split(' ').getOrNull(1)?.toIntOrNull() ?: return null
            val headers = HashMap<String, String>()
            while (true) {
                val line = readHttpHeaderLine(input)
                if (line.isEmpty()) break
                val idx = line.indexOf(':')
                if (idx > 0) headers[line.substring(0, idx).trim().lowercase(java.util.Locale.US)] = line.substring(idx + 1).trim()
            }
            val respBody = if (headers["transfer-encoding"].orEmpty().contains("chunked", ignoreCase = true)) {
                val acc = ByteArrayOutputStream()
                while (true) {
                    val size = readHttpHeaderLine(input).substringBefore(';').trim().toIntOrNull(16) ?: break
                    if (size == 0) break
                    if (acc.size() + size > Wire.MAX_BYTES) break
                    acc.write(readExactBytes(input, size))
                    readHttpHeaderLine(input)
                }
                acc.toByteArray()
            } else {
                val len = headers["content-length"]?.toIntOrNull() ?: return null
                if (len < 12 || len > Wire.MAX_BYTES) return null
                readExactBytes(input, len)
            }
            val type = headers["content-type"].orEmpty()
            if (status == 200 && type.startsWith("application/dns-message", ignoreCase = true) && respBody.size >= 12) {
                DohResponse(1, rtt(), EncProtocol.DOH, respBody)
            } else {
                DohResponse(6, rtt(), EncProtocol.DOH, null)
            }
        } catch (_: Throwable) {
            null
        } finally {
            runCatching { ssl?.close() }
            runCatching { tunnel?.close() }
        }
    }

    private fun dispatchPacket(raw: ByteArray) {
        if (raw.isNotEmpty() && ((raw[0].toInt() ushr 4) and 0x0F) == 6) {
            // IPv6 is not bridged: answer immediately so dual-stack apps switch to IPv4 without leak.
            ipv6Rejected.incrementAndGet()
            IpPackets.buildIcmpv6Unreachable(raw)?.let { writeTun(it) }
            return
        }
        val ip = IpPackets.parseIpv4(raw) ?: return
        when (ip.proto) {
            IpPackets.PROTO_UDP -> {
                val udp = IpPackets.parseUdp(raw, ip) ?: return
                if (udp.dstPort == 53) {
                    handleDnsUdp(udp)
                    return
                }
                if (activeHardenStunLeaks && (IpPackets.isStunBindingRequest(udp.payload) || IpPackets.isLeakRiskUdpPort(udp.dstPort))) {
                    // Prevent WebRTC/STUN/mDNS/SSDP IP discovery probes from exposing local/ISP IP addresses.
                    leaksBlocked.incrementAndGet()
                    IpPackets.buildIcmpv4Unreachable(raw)?.let { writeTun(it) }
                    return
                }
            }
            IpPackets.PROTO_TCP -> {
                val tcp = IpPackets.parseTcp(raw, ip) ?: return
                val blockLeakTcp = (activeHardenStunLeaks && IpPackets.isLeakRiskTcpPort(tcp.dstPort)) ||
                    (activeStrictKillSwitch && (tcp.dstPort == 853 || tcp.dstPort == 53))
                if (blockLeakTcp) {
                    if ((tcp.flags and IpPackets.TCP_RST) == 0) {
                        leaksBlocked.incrementAndGet()
                        val ackNum = (tcp.seq + maxOf(1, tcp.payload.size) + if ((tcp.flags and IpPackets.TCP_SYN) != 0) 1 else 0) and 0xFFFFFFFFL
                        writeTun(
                            IpPackets.buildIpv4Tcp(
                                srcIp = tcp.ip.dstIp,
                                dstIp = tcp.ip.srcIp,
                                srcPort = tcp.dstPort,
                                dstPort = tcp.srcPort,
                                seq = 0L,
                                ack = ackNum,
                                flags = IpPackets.TCP_RST or IpPackets.TCP_ACK,
                            ),
                        )
                    }
                    return
                }
            }
        }

        // Prevent pre-handshake real-IP leaks while automatic WARP WireGuard is negotiating.
        if (warpBootstrapping.get()) return

        // Built-in L3 WireGuard WARP route: masks public IP, encrypts all TCP/UDP/HTTP3/ICMP packets.
        val wt = warpTunnel
        val warpIp = warpClientIpInt
        if (wt != null && wt.established && warpIp != 0) {
            val natOut = IpPackets.rewriteIpv4Nat(raw, newSrcIp = warpIp, clampMss = 1240) ?: return
            recordWarpOutbound(natOut)
            if (wt.sendIpPacket(natOut)) {
                warpPacketsOut.incrementAndGet()
                bytesUp.addAndGet(natOut.size.toLong())
            }
            return
        }

        when (ip.proto) {
            IpPackets.PROTO_UDP -> {
                val udp = IpPackets.parseUdp(raw, ip) ?: return
                if (activeBlockQuic && udp.dstPort == 443) {
                    // When QUIC fallback protection is enabled, steer QUIC to fragmented TLS/TCP
                    // so ISP SNI/ECH inspection cannot drop the session.
                    quicFallbacks.incrementAndGet()
                    IpPackets.buildIcmpv4Unreachable(raw)?.let { writeTun(it) }
                } else if (exitRelay != null && activeStrictKillSwitch) {
                    // Never leak direct UDP datagrams around the TCP Exit Relay when Kill Switch is active.
                    leaksBlocked.incrementAndGet()
                    IpPackets.buildIcmpv4Unreachable(raw)?.let { writeTun(it) }
                } else {
                    handleUdp(udp)
                }
            }
            IpPackets.PROTO_TCP -> {
                val tcp = IpPackets.parseTcp(raw, ip) ?: return
                handleTcp(tcp)
            }
        }
    }

    private fun handleDnsUdp(udp: IpPackets.UdpDatagram) {
        val query = udp.payload
        if (query.size < 12) return
        dnsQueries.incrementAndGet()
        ioPool.execute {
            try {
                val answer = resolveDnsQuery(query, udp.ip.dstIp) ?: return@execute
                val reply = IpPackets.buildIpv4Udp(
                    srcIp = udp.ip.dstIp,
                    dstIp = udp.ip.srcIp,
                    srcPort = udp.dstPort,
                    dstPort = udp.srcPort,
                    payload = answer,
                )
                writeTun(reply)
            } catch (_: Throwable) {
            }
        }
    }

    private fun withId(msg: ByteArray, query: ByteArray): ByteArray {
        val fixed = msg.copyOf()
        fixed[0] = query[0]
        fixed[1] = query[1]
        return fixed
    }

    private fun resolveDnsQuery(query: ByteArray, @Suppress("UNUSED_PARAMETER") requestedServerIp: Int): ByteArray? {
        if (query.size < 12) return null
        val qname = IpPackets.parseDnsQuestionName(query)
        // 0) Privacy & Tracker Shield sinkhole before leaving the device
        if (activeBlockTrackers && qname != null && IpPackets.isTrackerOrAdDomain(qname)) {
            trackersBlocked.incrementAndGet()
            return IpPackets.buildDnsNxdomain(query)
        }
        // 0b) Suppress unbridged IPv6 AAAA lookups to eliminate dual-stack IPv6 leaks
        if (suppressIpv6Dns && IpPackets.parseDnsQuestionType(query) == 28) {
            aaaaSuppressed.incrementAndGet()
            return IpPackets.buildDnsNodataAaaa(query)
        }
        // 1) TTL-bounded cache keyed by the query without its ID
        val cacheKey = query.copyOfRange(2, query.size).joinToString("") { "%02x".format(java.util.Locale.US, it) }
        val now = System.currentTimeMillis()
        dnsCache[cacheKey]?.let { (softExpiry, hardExpiry, msg) ->
            if (softExpiry > now) {
                dnsCacheHits.incrementAndGet()
                return withId(msg, query)
            }
            if (hardExpiry > now) {
                dnsCacheHits.incrementAndGet()
                val bgClient = dohClient
                val bgRelay = exitRelay
                if ((bgRelay != null || bgClient != null) && dnsRefreshInFlight.add(cacheKey)) {
                    ioPool.execute {
                        try {
                            val dohWireBg = query.copyOf().also { it[0] = 0; it[1] = 0 }
                            val eps = dohEndpoints.filter(Doh::validEndpoint)
                            val ep = eps.getOrNull(preferredDoh.coerceIn(0, (eps.size - 1).coerceAtLeast(0)))
                            if (ep != null) {
                                val resp = if (bgRelay != null) {
                                    postDohViaRelay(bgRelay, ep, dohWireBg, 2200)
                                } else {
                                    bgClient?.post(ep, dohWireBg, 2200)
                                }
                                val body = resp?.body
                                if (resp?.transport == 1 && body != null && body.size >= 12 && !IpPackets.containsPoisonedDns(body)) {
                                    val ttl = (IpPackets.dnsMinTtl(body) ?: 30L).coerceIn(10L, 600L)
                                    val tNow = System.currentTimeMillis()
                                    dnsCache[cacheKey] = Triple(tNow + ttl * 1000L, tNow + ttl * 1000L + 1_800_000L, body)
                                }
                            }
                        } catch (_: Throwable) {
                        } finally {
                            dnsRefreshInFlight.remove(cacheKey)
                        }
                    }
                }
                return withId(msg, query)
            }
            dnsCache.remove(cacheKey)
        }
        fun remember(msg: ByteArray): ByteArray {
            if (qname != null) {
                IpPackets.dnsAnswerAddresses(msg)?.forEach { a ->
                    if (a.size == 4) {
                        val ipInt = ((a[0].toInt() and 0xFF) shl 24) or
                            ((a[1].toInt() and 0xFF) shl 16) or
                            ((a[2].toInt() and 0xFF) shl 8) or
                            (a[3].toInt() and 0xFF)
                        if (dnsIpToHost.size > 1024) dnsIpToHost.clear()
                        dnsIpToHost[ipInt] = qname
                    }
                }
            }
            val ttl = (IpPackets.dnsMinTtl(msg) ?: 30L).coerceIn(10L, 600L)
            if (dnsCache.size > 2048) dnsCache.clear()
            dnsCache[cacheKey] = Triple(now + ttl * 1000L, now + ttl * 1000L + 1_800_000L, msg)
            return withId(msg, query)
        }
        // 2) Encrypted DNS (RFC 8484, ID 0) — via Exit Relay first if active, else Happy Eyeballs parallel racing
        val endpoints = dohEndpoints.filter(Doh::validEndpoint)
        val dohWire = query.copyOf().also { it[0] = 0; it[1] = 0 }
        val relay = exitRelay
        if (relay != null && endpoints.isNotEmpty()) {
            val first = preferredDoh.coerceIn(0, endpoints.size - 1)
            for (k in endpoints.indices) {
                val idx = (first + k) % endpoints.size
                val resp = postDohViaRelay(relay, endpoints[idx], dohWire, 3500) ?: continue
                val body = resp.body
                if (resp.transport == 1 && body != null && body.size >= 12) {
                    if (IpPackets.containsPoisonedDns(body)) {
                        poisonedDnsBlocked.incrementAndGet()
                        continue
                    }
                    preferredDoh = idx
                    dohResolved.incrementAndGet()
                    return remember(body)
                }
            }
            if (activeStrictKillSwitch) {
                leaksBlocked.incrementAndGet()
                return null
            }
        }
        val client = dohClient
        if (client != null && endpoints.isNotEmpty()) {
            val first = preferredDoh.coerceIn(0, endpoints.size - 1)
            val tried = HashSet<Int>(2)
            if (endpoints.size >= 2) {
                val second = (first + 1) % endpoints.size
                tried.add(first)
                tried.add(second)
                val winner = AtomicReference<Pair<Int, ByteArray>?>(null)
                val done = CountDownLatch(1)
                val finished = AtomicInteger(0)
                for (cand in intArrayOf(first, second)) {
                    ioPool.execute {
                        try {
                            val resp = runCatching { client.post(endpoints[cand], dohWire, 2200) }.getOrNull()
                            val body = resp?.body
                            if (resp?.transport == 1 && body != null && body.size >= 12) {
                                if (IpPackets.containsPoisonedDns(body)) {
                                    poisonedDnsBlocked.incrementAndGet()
                                } else if (winner.compareAndSet(null, cand to body)) {
                                    done.countDown()
                                }
                            }
                        } finally {
                            if (finished.incrementAndGet() >= 2) done.countDown()
                        }
                    }
                }
                runCatching { done.await(2300, TimeUnit.MILLISECONDS) }
                winner.get()?.let { (winIdx, winBody) ->
                    preferredDoh = winIdx
                    dohResolved.incrementAndGet()
                    return remember(winBody)
                }
            }
            for (k in endpoints.indices) {
                val idx = (first + k) % endpoints.size
                if (!tried.add(idx)) continue
                val resp = runCatching { client.post(endpoints[idx], dohWire, 2500) }.getOrNull() ?: continue
                val body = resp.body
                if (resp.transport == 1 && body != null && body.size >= 12) {
                    if (IpPackets.containsPoisonedDns(body)) {
                        poisonedDnsBlocked.incrementAndGet()
                        continue
                    }
                    preferredDoh = idx
                    dohResolved.incrementAndGet()
                    return remember(body)
                }
            }
        }
        // Strict Kill Switch / masked tunnel modes prevent plaintext DNS fallback when encrypted DoH fails.
        if (activeStrictKillSwitch || isWarpActive || exitRelay != null || (autoWarp && warpBootstrapping.get())) {
            leaksBlocked.incrementAndGet()
            return null
        }
        // 3) Fallback: protected UDP to public resolvers only; injected/poisoned replies are skipped.
        for (srv in upstreamDnsServers) {
            if (srv.isBlank()) continue
            val host = srv.substringBefore(':')
            val port = srv.substringAfter(':', "53").toIntOrNull() ?: 53
            val sock = try {
                DatagramSocket()
            } catch (_: Exception) {
                continue
            }
            try {
                protectDatagram(sock)
                val target = InetSocketAddress(InetAddress.getByName(host), port)
                sock.send(DatagramPacket(query, query.size, target))
                val deadline = System.currentTimeMillis() + 2000
                val buf = ByteArray(4096)
                while (true) {
                    val left = deadline - System.currentTimeMillis()
                    if (left <= 0) break
                    sock.soTimeout = left.toInt()
                    val p = DatagramPacket(buf, buf.size)
                    sock.receive(p)
                    if (p.length < 12 || buf[0] != query[0] || buf[1] != query[1]) continue
                    val msg = buf.copyOf(p.length)
                    if (IpPackets.containsPoisonedDns(msg)) {
                        poisonedDnsBlocked.incrementAndGet()
                        continue
                    }
                    return remember(msg)
                }
            } catch (_: Exception) {
            } finally {
                runCatching { sock.close() }
            }
        }
        return null
    }

    private fun handleUdp(udp: IpPackets.UdpDatagram) {
        if (udp.payload.isEmpty()) return
        val key = FlowKey(udp.ip.srcIp, udp.srcPort, udp.ip.dstIp, udp.dstPort)
        if (udpTable.size > 512) {
            val oldest = udpTable.entries.sortedBy { it.value.lastActiveNs }.take(minOf(100, udpTable.size - 400))
            for (entry in oldest) {
                if (udpTable.remove(entry.key, entry.value)) entry.value.close()
            }
        }
        val flow = udpTable.computeIfAbsent(key) { k ->
            udpFlows.incrementAndGet()
            UdpFlow(k).also { it.start() }
        }
        flow.sendOutbound(udp.payload)
    }

    private inner class UdpFlow(val key: FlowKey) {
        @Volatile var lastActiveNs: Long = System.nanoTime()
        val socket: DatagramSocket? = runCatching {
            DatagramSocket().also {
                protectDatagram(it)
                runCatching { it.trafficClass = 0x10 }
                runCatching { it.receiveBufferSize = 65536; it.sendBufferSize = 65536 }
                it.soTimeout = 45_000
            }
        }.getOrNull()
        private val closed = AtomicBoolean(false)
        private val targetAddress: InetSocketAddress? = runCatching {
            val ip = if (key.dstIp == virtualDnsIp) {
                InetAddress.getByName(upstreamDnsServers.firstOrNull()?.substringBefore(':') ?: "1.1.1.1")
            } else {
                InetAddress.getByAddress(IpPackets.ipToBytes(key.dstIp))
            }
            InetSocketAddress(ip, key.dstPort)
        }.getOrNull()

        fun start() {
            val s = socket ?: return
            ioPool.execute {
                val buf = ByteArray(65535)
                while (running.get() && !closed.get()) {
                    try {
                        val dp = DatagramPacket(buf, buf.size)
                        s.receive(dp)
                        if (dp.length > 0) {
                            lastActiveNs = System.nanoTime()
                            bytesDown.addAndGet(dp.length.toLong())
                            val pkt = IpPackets.buildIpv4Udp(
                                srcIp = key.dstIp,
                                dstIp = key.srcIp,
                                srcPort = key.dstPort,
                                dstPort = key.srcPort,
                                payload = buf.copyOf(dp.length),
                            )
                            writeTun(pkt)
                        }
                    } catch (_: SocketTimeoutException) {
                        break
                    } catch (_: Throwable) {
                        break
                    }
                }
                close()
            }
        }

        fun sendOutbound(payload: ByteArray) {
            val s = socket ?: return
            val dst = targetAddress ?: return
            lastActiveNs = System.nanoTime()
            try {
                bytesUp.addAndGet(payload.size.toLong())
                s.send(DatagramPacket(payload, payload.size, dst))
            } catch (_: Throwable) {
                close()
            }
        }

        fun close() {
            if (closed.compareAndSet(false, true)) {
                udpTable.remove(key, this)
                runCatching { socket?.close() }
            }
        }
    }

    private fun handleTcp(tcp: IpPackets.TcpSegment) {
        val key = FlowKey(tcp.ip.srcIp, tcp.srcPort, tcp.ip.dstIp, tcp.dstPort)
        val isSyn = (tcp.flags and IpPackets.TCP_SYN) != 0 && (tcp.flags and IpPackets.TCP_ACK) == 0
        val isRst = (tcp.flags and IpPackets.TCP_RST) != 0
        val isFin = (tcp.flags and IpPackets.TCP_FIN) != 0

        if (isRst) {
            tcpTable.remove(key)?.close()
            return
        }
        if (isSyn) {
            if (tcpTable.size > 256) {
                val oldest = tcpTable.entries.sortedBy { it.value.lastActiveNs }.take(minOf(50, tcpTable.size - 200))
                for (entry in oldest) {
                    if (tcpTable.remove(entry.key, entry.value)) entry.value.close()
                }
            }
            tcpTable.remove(key)?.close()
            val flow = TcpFlow(key, (tcp.seq + 1L) and 0xFFFFFFFFL)
            tcpTable[key] = flow
            tcpFlows.incrementAndGet()
            flow.onSyn()
            return
        }
        val flow = tcpTable[key] ?: return
        if (tcp.payload.isNotEmpty()) {
            flow.onClientData(tcp)
        }
        if (isFin) {
            flow.onClientFin(tcp)
        }
    }

    private inner class TcpFlow(val key: FlowKey, var clientNextSeq: Long) {
        val lock = Any()
        var serverSeq: Long = (java.security.SecureRandom().nextInt().toLong() and 0xFFFFFFFFL)
        val closed = AtomicBoolean(false)
        @Volatile var lastActiveNs: Long = System.nanoTime()
        val outboundQueue = java.util.concurrent.LinkedBlockingQueue<ByteArray>(256)
        @Volatile var upstreamSocket: Socket? = null
        @Volatile var finFromClient = false
        var visionSpliced = false

        fun onSyn() {
            val synAckSeq: Long
            val ackNum: Long
            synchronized(lock) {
                lastActiveNs = System.nanoTime()
                synAckSeq = serverSeq
                ackNum = clientNextSeq
                serverSeq = (serverSeq + 1L) and 0xFFFFFFFFL
            }
            writeTun(
                IpPackets.buildIpv4Tcp(
                    srcIp = key.dstIp,
                    dstIp = key.srcIp,
                    srcPort = key.dstPort,
                    dstPort = key.srcPort,
                    seq = synAckSeq,
                    ack = ackNum,
                    flags = IpPackets.TCP_SYN or IpPackets.TCP_ACK,
                    mssOption = 1360,
                ),
            )
            ioPool.execute { connectAndPump() }
        }

        fun onClientData(tcp: IpPackets.TcpSegment) {
            val ackPkt: ByteArray
            synchronized(lock) {
                lastActiveNs = System.nanoTime()
                if (tcp.seq != clientNextSeq) {
                    ackPkt = IpPackets.buildIpv4Tcp(
                        srcIp = key.dstIp,
                        dstIp = key.srcIp,
                        srcPort = key.dstPort,
                        dstPort = key.srcPort,
                        seq = serverSeq,
                        ack = clientNextSeq,
                        flags = IpPackets.TCP_ACK,
                    )
                } else if (outboundQueue.offer(tcp.payload.copyOf())) {
                    clientNextSeq = (clientNextSeq + tcp.payload.size) and 0xFFFFFFFFL
                    ackPkt = IpPackets.buildIpv4Tcp(
                        srcIp = key.dstIp,
                        dstIp = key.srcIp,
                        srcPort = key.dstPort,
                        dstPort = key.srcPort,
                        seq = serverSeq,
                        ack = clientNextSeq,
                        flags = IpPackets.TCP_ACK,
                    )
                } else {
                    ackPkt = IpPackets.buildIpv4Tcp(
                        srcIp = key.dstIp,
                        dstIp = key.srcIp,
                        srcPort = key.dstPort,
                        dstPort = key.srcPort,
                        seq = serverSeq,
                        ack = clientNextSeq,
                        flags = IpPackets.TCP_ACK,
                    )
                }
            }
            writeTun(ackPkt)
        }

        fun onClientFin(tcp: IpPackets.TcpSegment) {
            val finAckPkt: ByteArray
            synchronized(lock) {
                lastActiveNs = System.nanoTime()
                if (((tcp.seq + tcp.payload.size) and 0xFFFFFFFFL) == clientNextSeq) {
                    clientNextSeq = (clientNextSeq + 1L) and 0xFFFFFFFFL
                    finFromClient = true
                }
                finAckPkt = IpPackets.buildIpv4Tcp(
                    srcIp = key.dstIp,
                    dstIp = key.srcIp,
                    srcPort = key.dstPort,
                    dstPort = key.srcPort,
                    seq = serverSeq,
                    ack = clientNextSeq,
                    flags = IpPackets.TCP_ACK,
                )
            }
            writeTun(finAckPkt)
        }

        private fun pumpOutbound(sock: Socket, out: OutputStream) {
            var firstPayloadDone = false
            var helloBuf: ByteArrayOutputStream? = null
            try {
                while (running.get() && !closed.get()) {
                    val payload = outboundQueue.poll(200, java.util.concurrent.TimeUnit.MILLISECONDS)
                    if (payload != null) {
                        lastActiveNs = System.nanoTime()
                        bytesUp.addAndGet(payload.size.toLong())
                        if (!firstPayloadDone) {
                            val acc = helloBuf
                            val data = if (acc != null) {
                                acc.write(payload)
                                acc.toByteArray()
                            } else {
                                payload
                            }
                            val isTls = data.size >= 5 && (data[0].toInt() and 0xFF) == 0x16 && (data[1].toInt() and 0xFF) == 0x03
                            if (isTls) {
                                val need = 5 + IpPackets.u16(data, 3)
                                if (data.size < need && need <= 16384 + 5) {
                                    if (acc == null) helloBuf = ByteArrayOutputStream().apply { write(data) }
                                    continue
                                }
                            }
                            helloBuf = null
                            firstPayloadDone = true
                            val personaSnap = currentDevicePersona
                            val sanitized = IpPackets.sanitizePlainHttpHeadersDetailed(
                                data,
                                persona = personaSnap,
                                stripGeoHeaders = personaSnap != DevicePersona.OFF,
                                stripTrackingParams = true,
                            )
                            val cleanData = sanitized.bytes
                            if (sanitized.leakBlocked) leaksBlocked.incrementAndGet()
                            if (sanitized.paramsStripped) paramsStripped.incrementAndGet()
                            if (sanitized.personaApplied) httpHeadersSpoofed.incrementAndGet()
                            if (exitRelay != null) {
                                out.write(cleanData)
                                out.flush()
                            } else {
                                val packet = IpPackets.buildIpv4Tcp(
                                    srcIp = key.srcIp, dstIp = key.dstIp, srcPort = key.srcPort, dstPort = key.dstPort,
                                    seq = 1L, ack = 1L, flags = IpPackets.TCP_PSH or IpPackets.TCP_ACK, payload = cleanData,
                                )
                                val res = runCatching { session.desyncPacket(packet, desyncConfig) }.getOrNull()
                                val nativeChunks = IpPackets.extractOrderedStreamChunks(packet, cleanData, res)
                                val chunks = IpPackets.planFirstPayload(cleanData, nativeChunks)
                                if (chunks.size > 1) {
                                    desyncedFlows.incrementAndGet()
                                }
                                if (isTls && chunks.size > 1 && chunks.all { it.size >= 5 && (it[0].toInt() and 0xFF) == 0x16 }) {
                                    tlsRecordFragmented.incrementAndGet()
                                }
                                if (desyncConfig.mode == DesyncMode.REALITY_VISION && isTls) {
                                    visionSpliced = true
                                    visionSplicedFlows.incrementAndGet()
                                }
                                for (i in chunks.indices) {
                                    out.write(chunks[i])
                                    out.flush()
                                    if (i < chunks.size - 1) {
                                        try { Thread.sleep(3) } catch (_: InterruptedException) { break }
                                    }
                                }
                            }
                        } else {
                            if (!visionSpliced && payload.size >= 5 && (payload[0].toInt() and 0xFF) == 0x17 && (payload[1].toInt() and 0xFF) == 0x03) {
                                visionSpliced = true
                                visionSplicedFlows.incrementAndGet()
                            }
                            out.write(payload)
                            out.flush()
                        }
                    } else if (finFromClient && outboundQueue.isEmpty()) {
                        runCatching { sock.shutdownOutput() }
                        break
                    }
                }
            } catch (_: Throwable) {
                close()
            }
        }

        private fun connectAndPump() {
            var pendingSock: Socket? = null
            try {
                if (key.dstIp == virtualDnsIp && activeStrictKillSwitch) {
                    leaksBlocked.incrementAndGet()
                    throw IOException("Strict Kill Switch blocks plaintext TCP DNS")
                }
                val relay = exitRelay
                val sock: Socket = if (relay != null) {
                    val targetHost = if (key.dstIp == virtualDnsIp) {
                        upstreamDnsServers.firstOrNull()?.substringBefore(':') ?: "1.1.1.1"
                    } else {
                        dnsIpToHost[key.dstIp] ?: IpPackets.ipToString(key.dstIp)
                    }
                    try {
                        openExitRelayTunnel(relay, targetHost, key.dstPort, 6000)
                    } catch (t: Throwable) {
                        leaksBlocked.incrementAndGet()
                        throw t
                    }
                } else {
                    Socket().also { s ->
                        pendingSock = s
                        s.bind(null)
                        protectSocket(s)
                        s.tcpNoDelay = true
                        runCatching { s.trafficClass = 0x10 }
                        runCatching { s.receiveBufferSize = 65536; s.sendBufferSize = 65536 }
                        runCatching { s.keepAlive = true }
                        s.soTimeout = 90_000
                        val dstInet = if (key.dstIp == virtualDnsIp) {
                            InetAddress.getByName(upstreamDnsServers.firstOrNull()?.substringBefore(':') ?: "1.1.1.1")
                        } else {
                            InetAddress.getByAddress(IpPackets.ipToBytes(key.dstIp))
                        }
                        s.connect(InetSocketAddress(dstInet, key.dstPort), 5000)
                    }
                }
                pendingSock = sock
                if (closed.get()) {
                    runCatching { sock.close() }
                    return
                }
                upstreamSocket = sock
                val out = sock.getOutputStream()
                ioPool.execute { pumpOutbound(sock, out) }

                val input = sock.getInputStream()
                val buf = ByteArray(1400)
                var firstInboundDone = false
                while (running.get() && !closed.get()) {
                    val n = input.read(buf)
                    if (n > 0) bytesDown.addAndGet(n.toLong())
                    if (n < 0) {
                        val finSeq: Long
                        val ackNum: Long
                        synchronized(lock) {
                            finSeq = serverSeq
                            ackNum = clientNextSeq
                            serverSeq = (serverSeq + 1L) and 0xFFFFFFFFL
                        }
                        writeTun(
                            IpPackets.buildIpv4Tcp(
                                srcIp = key.dstIp,
                                dstIp = key.srcIp,
                                srcPort = key.dstPort,
                                dstPort = key.srcPort,
                                seq = finSeq,
                                ack = ackNum,
                                flags = IpPackets.TCP_FIN or IpPackets.TCP_ACK,
                            ),
                        )
                        break
                    }
                    if (n > 0) {
                        lastActiveNs = System.nanoTime()
                        val rawChunk = buf.copyOf(n)
                        val outChunk = if (!firstInboundDone) {
                            firstInboundDone = true
                            if (activeBlockQuic) {
                                val (stripped, changed) = IpPackets.stripPlainHttpAltSvc(rawChunk)
                                if (changed) quicFallbacks.incrementAndGet()
                                stripped
                            } else {
                                rawChunk
                            }
                        } else {
                            rawChunk
                        }
                        val segSeq: Long
                        val ackNum: Long
                        synchronized(lock) {
                            segSeq = serverSeq
                            ackNum = clientNextSeq
                            serverSeq = (serverSeq + outChunk.size) and 0xFFFFFFFFL
                        }
                        writeTun(
                            IpPackets.buildIpv4Tcp(
                                srcIp = key.dstIp,
                                dstIp = key.srcIp,
                                srcPort = key.dstPort,
                                dstPort = key.srcPort,
                                seq = segSeq,
                                ack = ackNum,
                                flags = IpPackets.TCP_PSH or IpPackets.TCP_ACK,
                                payload = outChunk,
                            ),
                        )
                    }
                }
            } catch (_: Throwable) {
                runCatching { if (pendingSock !== upstreamSocket) pendingSock?.close() }
                val rstSeq: Long
                val ackNum: Long
                synchronized(lock) {
                    rstSeq = serverSeq
                    ackNum = clientNextSeq
                }
                writeTun(
                    IpPackets.buildIpv4Tcp(
                        srcIp = key.dstIp,
                        dstIp = key.srcIp,
                        srcPort = key.dstPort,
                        dstPort = key.srcPort,
                        seq = rstSeq,
                        ack = ackNum,
                        flags = IpPackets.TCP_RST or IpPackets.TCP_ACK,
                    ),
                )
            } finally {
                close()
            }
        }

        fun close() {
            if (closed.compareAndSet(false, true)) {
                tcpTable.remove(key, this)
                outboundQueue.clear()
                runCatching { upstreamSocket?.close() }
            }
        }
    }

    override fun close() {
        if (running.compareAndSet(true, false)) {
            runCatching { probeStack?.close() }
            probeStack = null
            runCatching { warpTunnel?.close() }
            warpTunnel = null
            warpFlows.clear()
            warpIcmpPending.clear()
            runCatching { tunInput.close() }
            runCatching { tunOutput.close() }
            readerThread?.interrupt()
            for (f in tcpTable.values) f.close()
            for (u in udpTable.values) u.close()
            tcpTable.clear()
            udpTable.clear()
            dnsCache.clear()
            dnsIpToHost.clear()
            ioPool.shutdownNow()
        }
    }

    companion object {
        const val VPN_CLIENT_IP = "10.215.173.1"
        const val VPN_DNS_IP = "10.215.173.2"
        val DEFAULT_DOH_ENDPOINTS = listOf(
            "https://1.1.1.1/dns-query",
            "https://8.8.8.8/dns-query",
            "https://9.9.9.9/dns-query",
            "https://cloudflare-dns.com/dns-query",
            "https://dns.google/dns-query",
            "https://dns.quad9.net/dns-query",
        )
        val DEFAULT_DNS_SERVERS = listOf("1.1.1.1", "8.8.8.8", "9.9.9.9")
    }
}

// ==================================================================================
// WINDOWS PLATFORM SECTION
// ==================================================================================

/** Windows platform services: native IP Helper detection, Windows cert store, and poison-resilient DoH probing. */
object WindowsPlatform {
    val trustContext: Pair<SSLContext, String> by lazy {
        try {
            val ks = KeyStore.getInstance("Windows-ROOT")
            ks.load(null, null)
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            tmf.init(ks)
            val ctx = SSLContext.getInstance("TLS")
            ctx.init(null, tmf.trustManagers, null)
            ctx to "Windows sertifika deposu"
        } catch (e: Exception) {
            val defaultTmf = runCatching {
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(null as KeyStore?) }
            }.getOrNull()
            val hasDefaultIssuers = defaultTmf?.trustManagers
                ?.filterIsInstance<javax.net.ssl.X509TrustManager>()
                ?.any { it.acceptedIssuers.isNotEmpty() } == true
            if (hasDefaultIssuers) {
                SSLContext.getDefault() to "JDK güven deposu"
            } else {
                val fallbackCtx = runCatching {
                    val pem = File("/etc/ssl/certs/ca-certificates.crt")
                    val ks = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null, null) }
                    if (pem.exists()) {
                        val cf = java.security.cert.CertificateFactory.getInstance("X.509")
                        pem.inputStream().use { inp ->
                            cf.generateCertificates(inp).forEachIndexed { idx, cert ->
                                ks.setCertificateEntry("sys-ca-$idx", cert)
                            }
                        }
                    }
                    if (ks.size() > 0) {
                        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(ks) }
                        SSLContext.getInstance("TLS").apply { init(null, tmf.trustManagers, null) }
                    } else null
                }.getOrNull()
                (fallbackCtx ?: SSLContext.getDefault()) to "JDK güven deposu"
            }
        }
    }

    val trust: Pair<SSLSocketFactory, String> get() = trustContext.first.socketFactory to trustContext.second

    fun dohClient(): DohClient = JdkDohClient(trustContext.first)

    private fun isIspPoisonedIp(host: String, addr: InetAddress): Boolean {
        val h = host.lowercase(Locale.US)
        val isLocalName = h == "localhost" || h.endsWith(".local") || h.endsWith(".test") || h.endsWith(".internal")
        val raw = addr.address
        if (raw.size == 4) {
            val b0 = raw[0].toInt() and 0xFF
            val b1 = raw[1].toInt() and 0xFF
            val b2 = raw[2].toInt() and 0xFF
            if (b0 == 195 && b1 == 175 && b2 == 254) return true // ISP block / warning splash IP
            if (b0 == 0) return true
            if (!isLocalName && (b0 == 127 || b0 == 10 || (b0 == 172 && b1 in 16..31) || (b0 == 192 && b1 == 168) || (b0 == 169 && b1 == 254))) {
                return true
            }
            return false
        }
        if (raw.size == 16) {
            if (!isLocalName && raw.copyOfRange(0, 15).all { it.toInt() == 0 }) return true
            val tt = byteArrayOf(0x2a, 0x01, 0x03, 0x58, 0x40, 0x14, 0x0a, 0x00)
            if (raw.copyOfRange(0, 8).contentEquals(tt)) return true
        }
        return false
    }

    private fun dohResolveClean(host: String, timeoutMs: Int): List<InetAddress> {
        val q = Doh.query(host, qtype = 1) ?: return emptyList()
        val out = ArrayList<InetAddress>()
        runCatching {
            DirectDohClient(sslFactory = trust.first).use { client ->
                for (ep in arrayOf("https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query", "https://9.9.9.9/dns-query")) {
                    val r = client.post(ep, q, timeoutMs.coerceIn(800, 3500))
                    val b = r.body
                    if (r.transport == 1 && b != null && !IpPackets.containsPoisonedDns(b)) {
                        IpPackets.dnsAnswerAddresses(b)?.forEach { raw ->
                            runCatching { out.add(InetAddress.getByAddress(raw)) }
                        }
                        if (out.isNotEmpty()) break
                    }
                }
            }
        }
        return out
    }

    fun prober(): TlsProber = TlsProber(trust.first, { host, port, timeout ->
        val literal = IpPackets.parseIpLiteral(host) != null || host.contains(':')
        if (literal) {
            return@TlsProber Socket().apply {
                tcpNoDelay = true
                connect(InetSocketAddress(host, port), timeout)
            }
        }
        val sysCandidates = runCatching {
            InetAddress.getAllByName(host).filter { !isIspPoisonedIp(host, it) }
        }.getOrDefault(emptyList())
        val ordered = (sysCandidates.ifEmpty { dohResolveClean(host, timeout) })
            .sortedBy { if (it is Inet4Address) 0 else 1 }
        if (ordered.isEmpty()) {
            throw IOException("Temiz DNS adresi çözümlenemedi: $host")
        }
        var lastErr: IOException? = null
        val perTry = maxOf(800, timeout / minOf(ordered.size, 3))
        for (addr in ordered.take(3)) {
            val s = Socket()
            try {
                s.tcpNoDelay = true
                s.connect(InetSocketAddress(addr, port), perTry)
                return@TlsProber s
            } catch (e: IOException) {
                runCatching { s.close() }
                lastErr = e
            }
        }
        throw lastErr ?: IOException("Bağlantı başarısız: $host:$port")
    })

    /** Native detection (GetAdaptersAddresses + registry); JDK fallback keeps unknowns unknown. */
    fun environment(dnsOverride: List<String> = emptyList()): EnvironmentInfo {
        val rec = Native.detectEnvironment()?.let { runCatching { Wire.decode(it) }.getOrNull() }
        var env = rec?.let { EnvironmentInfo.fromRecord(it) } ?: EnvironmentInfo()
        if (rec?.status?.toInt() != Codes.OK) env = jdkFallback(env)
        if (env.osVersion.isEmpty()) env = env.copy(osVersion = System.getProperty("os.version") ?: "")
        if (dnsOverride.isNotEmpty()) env = env.copy(dnsServers = dnsOverride)
        return env
    }

    private fun jdkFallback(base: EnvironmentInfo): EnvironmentInfo {
        val candidates = runCatching {
            NetworkInterface.networkInterfaces().toList().filter { it.isUp && !it.isLoopback && !it.isVirtual }
        }.getOrDefault(emptyList())
        val ni = candidates.firstOrNull { n -> n.inetAddresses.toList().any { !it.isLinkLocalAddress } }
            ?: return base.copy(osName = System.getProperty("os.name") ?: base.osName)
        val addrs = ni.inetAddresses.toList()
        return base.copy(
            osName = System.getProperty("os.name") ?: base.osName,
            interfaceName = ni.name,
            mtu = runCatching { ni.mtu }.getOrDefault(0),
            hasIpv4 = if (addrs.any { it is Inet4Address && !it.isLinkLocalAddress }) YES else NO,
            hasIpv6 = if (addrs.any { it is Inet6Address && !it.isLinkLocalAddress && !it.isSiteLocalAddress && (it.address[0].toInt() and 0xE0) == 0x20 }) YES else NO,
        )
    }
}

private fun splitList(s: String): List<String> =
    s.split('\n', ',', ' ', ';').map { it.trim() }.filter { it.isNotEmpty() }

/**
 * RFC 8484 DoH over the JDK HTTP client with the Windows trust store. HTTP/3 is requested
 * when the running JDK provides it (JEP 517); the protocol actually negotiated is reported,
 * so DoH3 is never claimed when HTTP/2 was used. Redirects are refused (a DoH endpoint
 * that redirects is treated as a failure, never followed into a login page).
 */
class JdkDohClient(private val ssl: SSLContext) : DohClient {
    private val client: HttpClient by lazy {
        HttpClient.newBuilder()
            .sslContext(ssl)
            .version(PREFERRED)
            .followRedirects(HttpClient.Redirect.NEVER)
            .proxy(ProxySelector.getDefault())
            .connectTimeout(Duration.ofSeconds(5))
            .build()
    }

    override fun post(url: String, body: ByteArray, timeoutMs: Int): DohResponse {
        val attempted = if (PREFERRED.name == "HTTP_3") EncProtocol.DOH3 else EncProtocol.DOH
        val start = System.nanoTime()
        fun rtt() = (System.nanoTime() - start) / 1000
        return try {
            val req = HttpRequest.newBuilder(URI(url))
                .timeout(Duration.ofMillis(timeoutMs.toLong()))
                .header("Content-Type", "application/dns-message")
                .header("Accept", "application/dns-message")
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .build()
            val resp = client.send(req, HttpResponse.BodyHandlers.ofByteArray())
            val proto = if (resp.version().name == "HTTP_3") EncProtocol.DOH3 else EncProtocol.DOH
            val type = resp.headers().firstValue("content-type").orElse("")
            if (resp.statusCode() == 200 && type.startsWith("application/dns-message", ignoreCase = true)) {
                val b = resp.body()
                DohResponse(1, rtt(), proto, if (b.size > Wire.MAX_BYTES) b.copyOf(Wire.MAX_BYTES) else b)
            } else {
                DohResponse(6, rtt(), proto, null)
            }
        } catch (e: HttpTimeoutException) {
            DohResponse(2, rtt(), attempted, null)
        } catch (e: ConnectException) {
            DohResponse(4, rtt(), attempted, null)
        } catch (e: IOException) {
            DohResponse(5, rtt(), attempted, null)
        } catch (e: IllegalArgumentException) {
            DohResponse(6, rtt(), attempted, null)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            DohResponse(5, rtt(), attempted, null)
        }
    }

    companion object {
        val PREFERRED: HttpClient.Version =
            runCatching { HttpClient.Version.valueOf("HTTP_3") }.getOrDefault(HttpClient.Version.HTTP_2)
    }
}

/** Outbound routing modes for Windows 10/11 Command Center & Next-Gen Proxy. */
enum class WindowsRouteMode(
    val id: String,
    val titleTr: String,
    val subtitleTr: String,
) {
    AUTO_WARP("auto_warp", "Otomatik WARP (IP Maskeli)", "WARP WireGuard -> Tor :9050 -> Hibrit DPI Yedeği"),
    HYBRID_DPI("hybrid_dpi", "Hızlı DPI + DoH3", "DoH3 Temiz DNS + Çoklu TLS Kayıt Bölme (Sahte Paketsiz)"),
    CUSTOM_RELAY("custom_relay", "Özel Röle / Tor", "Kişisel SOCKS5 / HTTP / HTTPS Çıkış Rölesi");

    companion object {
        fun fromId(raw: String?): WindowsRouteMode =
            values().firstOrNull { it.id.equals(raw?.trim(), ignoreCase = true) } ?: AUTO_WARP
    }
}

/** Thread-safe circular log ring buffer backing the Windows UI live log console. */
object WindowsLogBus {
    private const val MAX_LINES = 320
    private val lock = ReentrantLock()
    private val lines = ArrayList<String>(MAX_LINES)
    private val timeFmt = object : ThreadLocal<SimpleDateFormat>() {
        override fun initialValue(): SimpleDateFormat = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)
    }
    val version = AtomicLong(0L)

    fun append(tag: String, msg: String) {
        val ts = timeFmt.get()!!.format(Date())
        val entry = "[$ts] [$tag] $msg"
        lock.lock()
        try {
            if (lines.size >= MAX_LINES) lines.removeAt(0)
            lines.add(entry)
            version.incrementAndGet()
        } finally {
            lock.unlock()
        }
    }

    fun snapshot(): Pair<Long, String> {
        lock.lock()
        return try {
            version.get() to lines.joinToString("\n")
        } finally {
            lock.unlock()
        }
    }

    fun clear() {
        lock.lock()
        try {
            lines.clear()
            version.incrementAndGet()
        } finally {
            lock.unlock()
        }
    }
}

/**
 * Isolated Privacy Browser Launcher for Chrome / Edge / Brave on Windows:
 * pre-writes Chromium `Preferences` and supplies launch flags that eliminate
 * `ERR_QUIC_PROTOCOL_ERROR`, WebRTC local/public IP leaks, browser async DNS bypass,
 * and expose synthetic User-Agent personas consistently across HTTPS targets.
 */
object WindowsBrowserLauncher {
    data class BrowserInstall(val name: String, val exePath: String)

    fun appDataDir(): File {
        val localAppData = System.getenv("LOCALAPPDATA")?.takeIf { it.isNotBlank() }
        val base = if (localAppData != null) File(localAppData) else File(System.getProperty("java.io.tmpdir"), "freedom-network")
        return File(base, "FreedomNetwork").apply { runCatching { mkdirs() } }
    }

    fun warpIdentityFile(): File = File(appDataDir(), "warp_identity.dat")

    fun defaultProfileDir(): File = File(appDataDir(), "BrowserProfile").apply { runCatching { mkdirs() } }

    fun detectBrowsers(): List<BrowserInstall> {
        val pf = System.getenv("ProgramFiles")?.takeIf { it.isNotBlank() } ?: "C:\\Program Files"
        val pf86 = System.getenv("ProgramFiles(x86)")?.takeIf { it.isNotBlank() } ?: "C:\\Program Files (x86)"
        val local = System.getenv("LOCALAPPDATA")?.takeIf { it.isNotBlank() } ?: ""
        val candidates = listOf(
            "Google Chrome" to listOf(
                "$pf\\Google\\Chrome\\Application\\chrome.exe",
                "$pf86\\Google\\Chrome\\Application\\chrome.exe",
                "$local\\Google\\Chrome\\Application\\chrome.exe",
            ),
            "Microsoft Edge" to listOf(
                "$pf86\\Microsoft\\Edge\\Application\\msedge.exe",
                "$pf\\Microsoft\\Edge\\Application\\msedge.exe",
            ),
            "Brave" to listOf(
                "$pf\\BraveSoftware\\Brave-Browser\\Application\\brave.exe",
                "$pf86\\BraveSoftware\\Brave-Browser\\Application\\brave.exe",
                "$local\\BraveSoftware\\Brave-Browser\\Application\\brave.exe",
            ),
        )
        val found = ArrayList<BrowserInstall>()
        for ((name, paths) in candidates) {
            val hit = paths.firstOrNull { p -> p.isNotBlank() && File(p).let { it.exists() && it.isFile } }
            if (hit != null) found.add(BrowserInstall(name, hit))
        }
        return found
    }

    fun prepareProfilePreferences(profileRoot: File = defaultProfileDir(), blockLocation: Boolean = true): File {
        val defDir = File(profileRoot, "Default").apply { mkdirs() }
        val prefFile = File(defDir, "Preferences")
        val geoVal = if (blockLocation) 2 else 3
        val json = """
            {
              "webrtc": {
                "ip_handling_policy": "disable_non_proxied_udp",
                "multiple_routes_enabled": false,
                "nonproxied_udp_enabled": false
              },
              "async_dns": {
                "enabled": false
              },
              "dns_over_https": {
                "mode": "off"
              },
              "browser": {
                "enable_do_not_track": true
              },
              "profile": {
                "default_content_setting_values": {
                  "geolocation": $geoVal,
                  "notifications": 2,
                  "sensors": 2
                }
              }
            }
        """.trimIndent()
        prefFile.writeText(json, Charsets.UTF_8)
        return prefFile
    }

    fun buildLaunchArgs(
        exePath: String,
        proxyPort: Int,
        persona: DevicePersona,
        initialUrl: String = "",
        profileRoot: File = defaultProfileDir(),
    ): List<String> {
        val args = ArrayList<String>(14)
        args.add(exePath)
        args.add("--user-data-dir=${profileRoot.absolutePath}")
        args.add("--proxy-server=http://127.0.0.1:$proxyPort")
        args.add("--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1")
        args.add("--disable-quic")
        args.add("--force-webrtc-ip-handling-policy=disable_non_proxied_udp")
        args.add("--enforce-webrtc-ip-permission-check")
        args.add("--disable-features=AsyncDns,UseDnsHttpsSvcb")
        args.add("--no-first-run")
        args.add("--no-default-browser-check")
        if (persona != DevicePersona.OFF && persona.userAgent.isNotEmpty()) {
            args.add("--user-agent=${persona.userAgent}")
        }
        if (initialUrl.isNotBlank()) {
            args.add(initialUrl.trim())
        }
        return args
    }

    fun launch(
        proxyPort: Int,
        persona: DevicePersona,
        initialUrl: String = "https://discord.com/",
        preferredBrowserIndex: Int = 0,
        blockLocation: Boolean = true,
    ): Pair<Boolean, String> {
        if (proxyPort !in 1..65535) return false to "Önce Özgür Ağı başlatın (yerel vekil portu etkin değil)"
        val browsers = detectBrowsers()
        val chosen = browsers.getOrNull(preferredBrowserIndex) ?: browsers.firstOrNull()
            ?: return false to "Chrome / Edge / Brave bulunamadı; sistem vekili açıkken mevcut tarayıcınızı kullanabilirsiniz"
        return try {
            val profile = defaultProfileDir()
            prepareProfilePreferences(profile, blockLocation = blockLocation)
            val cmd = buildLaunchArgs(chosen.exePath, proxyPort, persona, initialUrl, profile)
            ProcessBuilder(cmd).start()
            WindowsLogBus.append("Browser", "${chosen.name} başlatıldı -> ${initialUrl.ifBlank { "yeni sekme" }} (proxy=127.0.0.1:$proxyPort, QUIC=kapalı, WebRTC=kilidi, persona=${persona.shortLabel})")
            true to "${chosen.name} korumalı profil ile açıldı (QUIC kapalı · WebRTC kilitli)"
        } catch (t: Throwable) {
            WindowsLogBus.append("Browser", "Başlatma hatası (${chosen.name}): ${t.message}")
            false to "Tarayıcı başlatılamadı: ${t.message}"
        }
    }
}

/**
 * Windows 10/11 Next-Gen Proxy Engine (HTTP / HTTPS CONNECT / SOCKS5 on one local listener):
 * 1. `AUTO_WARP`: Pure-Kotlin WireGuard WARP via [UserspaceTcpStack] (real IP masking without admin rights)
 *    with seamless failover to local Tor `:9050` or Hybrid DPI+DoH3 if UDP is firewalled.
 * 2. `HYBRID_DPI`: Poison-filtered DoH3 + TCP-DNS fallback + Happy Eyeballs multi-IP + safe multi-record
 *    TLS `0x16` SNI/ECH fragmentation (zero stream-corrupting decoy bytes) with automatic immediate-RST retry.
 * 3. Privacy & Leak Shield: Tracker domain blocking (`403`), STUN/QUIC UDP rejection, URL tracking param
 *    stripping, geo/IP header removal, and HTTP [DevicePersona] header spoofing.
 */
class WindowsNextGenProxy(
    private val port: Int = 0,
    val routeMode: WindowsRouteMode = WindowsRouteMode.AUTO_WARP,
    @Volatile private var customRelayUri: String = "",
    @Volatile var persona: DevicePersona = DevicePersona.IPHONE_19_BETA,
    @Volatile private var blockTrackers: Boolean = true,
    @Volatile private var stripUrlParams: Boolean = true,
    @Volatile private var blockQuicAndLeaks: Boolean = true,
    private val dohEndpoints: List<String> = TunBridge.DEFAULT_DOH_ENDPOINTS,
    private val upstreamDnsServers: List<String> = TunBridge.DEFAULT_DNS_SERVERS,
    private val dohClient: DohClient? = null,
    private val warpIdentityOverride: WarpIdentity? = null,
    private val warpFactory: ((WarpIdentity) -> WarpTunnel)? = null,
    private val onWarpIdentityReady: ((WarpIdentity) -> Unit)? = null,
    private val onRouteUpdated: ((String, Boolean) -> Unit)? = null,
    private val forceDirectForLoopback: Boolean = true,
    private val allowLoopbackDns: Boolean = false,
    private val preferredDesyncMode: Int = DesyncMode.ADAPTIVE_FULL,
) : AutoCloseable {
    private interface UpstreamChannel : Closeable {
        val inputStream: InputStream
        val outputStream: OutputStream
        fun setSoTimeout(ms: Int)
        fun shutdownOutput()
    }

    private class TcpSocketChannel(val sock: Socket) : UpstreamChannel {
        override val inputStream: InputStream get() = sock.inputStream
        override val outputStream: OutputStream get() = sock.outputStream
        override fun setSoTimeout(ms: Int) { sock.soTimeout = ms }
        override fun shutdownOutput() { runCatching { sock.shutdownOutput() } }
        override fun close() { runCatching { sock.close() } }
    }

    private class UserspaceChannel(val sock: UserspaceTcpStack.UserspaceTcpSocket) : UpstreamChannel {
        override val inputStream: InputStream get() = sock.inputStream
        override val outputStream: OutputStream get() = sock.outputStream
        override fun setSoTimeout(ms: Int) { sock.soTimeoutMs = ms }
        override fun shutdownOutput() { runCatching { sock.shutdownOutput() } }
        override fun close() { runCatching { sock.close() } }
    }

    private val running = AtomicBoolean(false)
    private var serverSocket: ServerSocket? = null
    private var acceptThread: Thread? = null
    private var internalDoh: DirectDohClient? = null
    private val rng = SecureRandom()
    private val ioPool: ExecutorService = Executors.newCachedThreadPool { r ->
        Thread(r, "freedom-win-proxy").apply { isDaemon = true }
    }

    @Volatile private var warpTunnel: WarpTunnel? = null
    @Volatile private var warpStack: UserspaceTcpStack? = null
    @Volatile private var warpReadyLatch: CountDownLatch? = null
    @Volatile private var activeRelay: ExitRelayConfig? =
        if (routeMode == WindowsRouteMode.CUSTOM_RELAY) ExitRelayConfig.parse(customRelayUri) else null
    @Volatile var routeLabel: String = when (routeMode) {
        WindowsRouteMode.AUTO_WARP -> "WARP WireGuard Bağlanıyor..."
        WindowsRouteMode.HYBRID_DPI -> "Hibrit DPI + DoH3 (Çoklu TLS Kayıt Bölme)"
        WindowsRouteMode.CUSTOM_RELAY -> activeRelay?.label() ?: "Özel Röle Bekleniyor"
    }
        private set
    @Volatile var isIpMasked: Boolean = (routeMode == WindowsRouteMode.CUSTOM_RELAY && activeRelay != null)
        private set
    @Volatile var localPort: Int = 0
        private set
    val isActive: Boolean get() = running.get() && localPort > 0

    private val dnsCache = ConcurrentHashMap<String, Pair<Long, List<InetAddress>>>()
    private val hostStrategyCache = ConcurrentHashMap<String, Int>()

    val connections = AtomicLong(0L)
    val tlsSplit = AtomicLong(0L)
    val tlsAdaptiveRetries = AtomicLong(0L)
    val httpSplit = AtomicLong(0L)
    val fakeSent = AtomicLong(0L)
    val rstDropped = AtomicLong(0L)
    val visionSplice = AtomicLong(0L)
    val trackersBlocked = AtomicLong(0L)
    val paramsStripped = AtomicLong(0L)
    val leaksBlocked = AtomicLong(0L)
    val dohResolved = AtomicLong(0L)
    val poisonedDnsBlocked = AtomicLong(0L)
    val warpFlows = AtomicLong(0L)
    val bytesUp = AtomicLong(0L)
    val bytesDown = AtomicLong(0L)

    fun updateSettings(
        customRelayUri: String? = null,
        blockTrackers: Boolean? = null,
        stripUrlParams: Boolean? = null,
        blockQuicAndLeaks: Boolean? = null,
        devicePersona: DevicePersona? = null,
    ) {
        if (blockTrackers != null) this.blockTrackers = blockTrackers
        if (stripUrlParams != null) this.stripUrlParams = stripUrlParams
        if (blockQuicAndLeaks != null) this.blockQuicAndLeaks = blockQuicAndLeaks
        if (devicePersona != null) this.persona = devicePersona
        if (customRelayUri != null) {
            val trimmed = customRelayUri.trim()
            this.customRelayUri = trimmed
            if (routeMode == WindowsRouteMode.CUSTOM_RELAY) {
                val parsed = ExitRelayConfig.parse(trimmed)
                this.activeRelay = parsed
                this.isIpMasked = parsed != null
                this.routeLabel = parsed?.label() ?: "Özel Röle Bekleniyor"
                onRouteUpdated?.invoke(this.routeLabel, this.isIpMasked)
            }
        }
    }

    fun statusSnapshot(): ProxyStatus = ProxyStatus(
        status = Codes.OK,
        active = isActive,
        port = localPort,
        mode = if (isIpMasked) DesyncMode.REALITY_VISION else preferredDesyncMode,
        connections = connections.get(),
        tlsSplit = tlsSplit.get(),
        httpSplit = httpSplit.get(),
        fakeSent = fakeSent.get(),
        rstDropped = rstDropped.get(),
        visionSplice = visionSplice.get(),
        trackersBlocked = trackersBlocked.get(),
        paramsStripped = paramsStripped.get(),
    )

    fun start(): Int {
        if (!running.compareAndSet(false, true)) return localPort
        val ss = ServerSocket()
        ss.reuseAddress = true
        ss.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), port.coerceIn(0, 65535)), 128)
        serverSocket = ss
        localPort = ss.localPort
        if (dohClient == null) {
            internalDoh = DirectDohClient(sslFactory = WindowsPlatform.trust.first)
        }
        WindowsLogBus.append("Proxy", "Yerel motor dinliyor: 127.0.0.1:$localPort (HTTP/HTTPS + SOCKS5, mod=${routeMode.id})")
        if (routeMode == WindowsRouteMode.AUTO_WARP) {
            val latch = CountDownLatch(1)
            warpReadyLatch = latch
            ioPool.execute {
                try {
                    bootstrapAutoWarp()
                } finally {
                    latch.countDown()
                }
            }
        } else {
            warpReadyLatch = null
            onRouteUpdated?.invoke(routeLabel, isIpMasked)
        }
        acceptThread = Thread({ acceptLoop(ss) }, "freedom-proxy-accept").apply {
            isDaemon = true
            start()
        }
        return localPort
    }

    private fun isLocalPortOpen(host: String, p: Int, timeoutMs: Int = 450): Boolean = runCatching {
        Socket().use { s -> s.connect(InetSocketAddress(InetAddress.getByName(host), p), timeoutMs) }
        true
    }.getOrDefault(false)

    private fun bootstrapAutoWarp() {
        try {
            var id = warpIdentityOverride?.takeIf { it.isValid() }
            if (id == null) {
                id = runCatching {
                    val f = WindowsBrowserLauncher.warpIdentityFile()
                    if (f.exists()) WarpIdentity.deserialize(f.readText(Charsets.UTF_8)) else null
                }.getOrNull()
            }
            var freshlyProvisioned = false
            if (id == null && running.get()) {
                WindowsLogBus.append("WARP", "Cloudflare WARP WireGuard hesabı oluşturuluyor...")
                id = WarpProvisioner.register(logger = { tag, m -> WindowsLogBus.append(tag, m) })
                freshlyProvisioned = id != null
                if (id != null) {
                    runCatching { WindowsBrowserLauncher.warpIdentityFile().writeText(id.serialize(), Charsets.UTF_8) }
                    onWarpIdentityReady?.invoke(id)
                }
            }
            if (id != null && running.get()) {
                val wt = warpFactory?.invoke(id) ?: WarpTunnel(id, logger = { tag, m -> WindowsLogBus.append(tag, m) })
                if (wt.connect(3200)) {
                    activateWarpTunnel(id, wt)
                    return
                }
                wt.close()
                if (!freshlyProvisioned && warpIdentityOverride == null && running.get()) {
                    val fresh = WarpProvisioner.register(logger = { tag, m -> WindowsLogBus.append(tag, m) })
                    if (fresh != null) {
                        runCatching { WindowsBrowserLauncher.warpIdentityFile().writeText(fresh.serialize(), Charsets.UTF_8) }
                        onWarpIdentityReady?.invoke(fresh)
                        val wt2 = warpFactory?.invoke(fresh) ?: WarpTunnel(fresh, logger = { tag, m -> WindowsLogBus.append(tag, m) })
                        if (wt2.connect(3200)) {
                            activateWarpTunnel(fresh, wt2)
                            return
                        }
                        wt2.close()
                    }
                }
            }
            if (running.get() && isLocalPortOpen("127.0.0.1", 9050, 450)) {
                activeRelay = ExitRelayConfig("socks5", "127.0.0.1", 9050)
                isIpMasked = true
                routeLabel = "Tor / Orbot (127.0.0.1:9050)"
                WindowsLogBus.append("WARP", "WARP UDP el sıkışması engelli; otomatik Tor/Orbot yedeği devreye alındı")
                warpReadyLatch?.countDown()
                onRouteUpdated?.invoke(routeLabel, true)
                return
            }
        } catch (t: Throwable) {
            WindowsLogBus.append("WARP", "Otomatik WARP başlatma hatası: ${t.message}")
        } finally {
            warpReadyLatch?.countDown()
        }
        if (running.get()) {
            isIpMasked = false
            routeLabel = "Hibrit DPI + DoH3 (WARP UDP Engelli)"
            WindowsLogBus.append("Route", "Yedek moda geçildi: $routeLabel")
            onRouteUpdated?.invoke(routeLabel, false)
        }
    }

    private fun activateWarpTunnel(id: WarpIdentity, wt: WarpTunnel) {
        val clientIp = id.clientIpInt() ?: IpPackets.parseIpLiteral("172.16.0.2")!!
        val stack = UserspaceTcpStack(clientIp, sendRawIp = { pkt -> wt.sendIpPacket(pkt) }, mtu = 1280)
        warpTunnel = wt
        warpStack = stack
        wt.startLoops { dec -> stack.onInboundIpPacket(dec) }
        val ep = wt.activeEndpoint?.let { "${it.hostString}:${it.port}" } ?: "${id.endpointHost}:${id.endpointPort}"
        isIpMasked = true
        routeLabel = "WARP WireGuard ($ep · ${wt.handshakeRttMs}ms)"
        warpReadyLatch?.countDown()
        WindowsLogBus.append("WARP", "Aktif tünel: $routeLabel · iç IP=${id.clientIpv4}")
        onRouteUpdated?.invoke(routeLabel, true)
    }

    private fun acceptLoop(ss: ServerSocket) {
        while (running.get() && !ss.isClosed) {
            val client = try {
                ss.accept()
            } catch (_: Throwable) {
                break
            }
            ioPool.execute {
                runCatching {
                    client.tcpNoDelay = true
                    client.soTimeout = 30_000
                    handleClient(client)
                }.onFailure {
                    runCatching { client.close() }
                }
            }
        }
    }

    private fun isPoisonedBytes(host: String, raw: ByteArray): Boolean {
        val h = host.lowercase(Locale.US)
        val allowLocal = h == "localhost" || h.endsWith(".local") || h.endsWith(".test") || h.endsWith(".internal")
        if (raw.size == 4) {
            val b0 = raw[0].toInt() and 0xFF
            val b1 = raw[1].toInt() and 0xFF
            val b2 = raw[2].toInt() and 0xFF
            if (b0 == 195 && b1 == 175 && b2 == 254) return true
            if (b0 == 0) return true
            if (!allowLocal && (b0 == 127 || b0 == 10 || (b0 == 172 && b1 in 16..31) || (b0 == 192 && b1 == 168) || (b0 == 169 && b1 == 254) || (b0 == 100 && b1 in 64..127))) {
                return true
            }
            return false
        }
        if (raw.size == 16) {
            if (!allowLocal && raw.copyOfRange(0, 15).all { it.toInt() == 0 }) return true
            val tt = byteArrayOf(0x2a, 0x01, 0x03, 0x58, 0x40, 0x14, 0x0a, 0x00)
            if (raw.copyOfRange(0, 8).contentEquals(tt)) return true
        }
        return false
    }

    private fun buildDnsQueryA(host: String): ByteArray? {
        Doh.query(host, 1)?.let { return it }
        val labels = host.trimEnd('.').split('.').filter { it.isNotEmpty() }
        if (labels.isEmpty()) return null
        val out = ByteArrayOutputStream()
        out.write(rng.nextInt(256)); out.write(rng.nextInt(256))
        out.write(0x01); out.write(0x00)
        out.write(0); out.write(1)
        out.write(0); out.write(0); out.write(0); out.write(0); out.write(0); out.write(0)
        for (l in labels) {
            val lb = l.toByteArray(Charsets.US_ASCII)
            if (lb.size > 63) return null
            out.write(lb.size)
            out.write(lb)
        }
        out.write(0)
        out.write(0); out.write(1) // QTYPE A
        out.write(0); out.write(1) // QCLASS IN
        return out.toByteArray()
    }

    private fun queryTcpDns(serverIp: String, query: ByteArray): ByteArray? = runCatching {
        Socket().use { s ->
            s.tcpNoDelay = true
            s.connect(InetSocketAddress(InetAddress.getByName(serverIp), 53), 1800)
            s.soTimeout = 1800
            val lenBuf = byteArrayOf(((query.size ushr 8) and 0xFF).toByte(), (query.size and 0xFF).toByte())
            s.outputStream.write(lenBuf)
            s.outputStream.write(query)
            s.outputStream.flush()
            val inp = s.inputStream
            val b0 = inp.read(); val b1 = inp.read()
            if (b0 < 0 || b1 < 0) return null
            val respLen = (b0 shl 8) or b1
            if (respLen !in 12..8192) return null
            readExact(inp, respLen)
        }
    }.getOrNull()

    private fun resolveTargetIps(host: String): List<InetAddress> {
        val literalV4 = IpPackets.parseIpLiteral(host)
        if (literalV4 != null) return listOf(InetAddress.getByAddress(IpPackets.ipToBytes(literalV4)))
        if (host.contains(':')) return listOf(InetAddress.getByName(host))

        val lower = host.lowercase(Locale.US)
        if (lower == "localhost" || lower.endsWith(".local") || lower.endsWith(".test")) {
            return runCatching { InetAddress.getAllByName(host).toList() }.getOrDefault(emptyList())
        }

        val now = System.currentTimeMillis()
        dnsCache[lower]?.let { (exp, addrs) -> if (now < exp && addrs.isNotEmpty()) return addrs }

        val query = buildDnsQueryA(lower)
        val client = dohClient ?: internalDoh
        val resolved = ArrayList<InetAddress>()
        if (query != null && client != null) {
            for (ep in dohEndpoints) {
                val r = runCatching { client.post(ep, query, 2400) }.getOrNull() ?: continue
                val body = r.body
                if (r.transport == 1 && body != null) {
                    val rawAddrs = IpPackets.dnsAnswerAddresses(body).orEmpty()
                    val loopbackOverride = allowLoopbackDns && dohClient != null && rawAddrs.isNotEmpty() && rawAddrs.all { raw ->
                        (raw.size == 4 && (raw[0].toInt() and 0xFF) == 127) ||
                            (raw.size == 16 && runCatching { InetAddress.getByAddress(raw).isLoopbackAddress }.getOrDefault(false))
                    }
                    if (!loopbackOverride && IpPackets.containsPoisonedDns(body)) {
                        poisonedDnsBlocked.incrementAndGet()
                        WindowsLogBus.append("DNS", "Zehirli yanıt engellendi ($ep -> $lower)")
                        continue
                    }
                    rawAddrs.forEach { raw ->
                        if (loopbackOverride || !isPoisonedBytes(lower, raw)) {
                            runCatching { resolved.add(InetAddress.getByAddress(raw)) }
                        }
                    }
                    if (resolved.isNotEmpty()) {
                        dohResolved.incrementAndGet()
                        val ttl = (IpPackets.dnsMinTtl(body) ?: 60L).coerceIn(30L, 600L)
                        val ordered = resolved.sortedBy { if (it is Inet4Address) 0 else 1 }
                        dnsCache[lower] = (now + ttl * 1000L) to ordered
                        return ordered
                    }
                }
            }
        }
        if (query != null) {
            for (dnsIp in upstreamDnsServers) {
                val tcpResp = queryTcpDns(dnsIp.substringBefore(':'), query) ?: continue
                if (!IpPackets.containsPoisonedDns(tcpResp)) {
                    IpPackets.dnsAnswerAddresses(tcpResp)?.forEach { raw ->
                        if (!isPoisonedBytes(lower, raw)) {
                            runCatching { resolved.add(InetAddress.getByAddress(raw)) }
                        }
                    }
                    if (resolved.isNotEmpty()) {
                        val ordered = resolved.sortedBy { if (it is Inet4Address) 0 else 1 }
                        dnsCache[lower] = (now + 60_000L) to ordered
                        return ordered
                    }
                } else {
                    poisonedDnsBlocked.incrementAndGet()
                }
            }
        }
        val sys = runCatching {
            InetAddress.getAllByName(host).filter { !isPoisonedBytes(lower, it.address) }
        }.getOrDefault(emptyList()).sortedBy { if (it is Inet4Address) 0 else 1 }
        if (sys.isNotEmpty()) dnsCache[lower] = (now + 30_000L) to sys
        return sys
    }

    private fun isLiteralLoopback(host: String): Boolean {
        val h = host.lowercase(Locale.US).trim('[', ']')
        if (h == "127.0.0.1" || h == "localhost" || h == "::1") return true
        val v4 = IpPackets.parseIpLiteral(h)
        if (v4 != null) return ((v4 ushr 24) and 0xFF) == 127
        if (h.contains(':')) {
            return runCatching { InetAddress.getByName(h).isLoopbackAddress }.getOrDefault(false)
        }
        return false
    }

    private fun isLoopbackDest(host: String, addrs: List<InetAddress>): Boolean {
        if (isLiteralLoopback(host)) return true
        return addrs.any { it.isLoopbackAddress }
    }

    private fun openExitRelay(relay: ExitRelayConfig, dstHost: String, dstPort: Int): UpstreamChannel {
        val raw = Socket()
        try {
            raw.tcpNoDelay = true
            raw.connect(InetSocketAddress(InetAddress.getByName(relay.host), relay.port), 5500)
            raw.soTimeout = 30_000
            val s: Socket = if (relay.scheme == "https") {
                val ssl = WindowsPlatform.trust.first.createSocket(raw, relay.host, relay.port, true) as SSLSocket
                val p = ssl.sslParameters
                p.endpointIdentificationAlgorithm = "HTTPS"
                ssl.sslParameters = p
                ssl.startHandshake()
                ssl
            } else {
                raw
            }
            val inp = s.inputStream
            val out = s.outputStream
            if (relay.scheme == "socks5") {
                val hasAuth = relay.username.isNotEmpty() || relay.password.isNotEmpty()
                out.write(if (hasAuth) byteArrayOf(0x05, 0x02, 0x00, 0x02) else byteArrayOf(0x05, 0x01, 0x00))
                out.flush()
                val choice = readExact(inp, 2)
                if (choice[0].toInt() != 0x05) throw IOException("SOCKS5 bad version")
                if ((choice[1].toInt() and 0xFF) == 0x02) {
                    val u = relay.username.toByteArray(Charsets.UTF_8).take(255).toByteArray()
                    val p = relay.password.toByteArray(Charsets.UTF_8).take(255).toByteArray()
                    val auth = ByteArray(3 + u.size + p.size)
                    auth[0] = 0x01; auth[1] = u.size.toByte()
                    System.arraycopy(u, 0, auth, 2, u.size)
                    auth[2 + u.size] = p.size.toByte()
                    System.arraycopy(p, 0, auth, 3 + u.size, p.size)
                    out.write(auth); out.flush()
                    val ar = readExact(inp, 2)
                    if (ar[1].toInt() != 0) throw IOException("SOCKS5 auth failed")
                } else if ((choice[1].toInt() and 0xFF) != 0x00) {
                    throw IOException("SOCKS5 unsupported auth")
                }
                val hostBytes = dstHost.toByteArray(Charsets.US_ASCII).take(255).toByteArray()
                val req = ByteArray(7 + hostBytes.size)
                req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03
                req[4] = hostBytes.size.toByte()
                System.arraycopy(hostBytes, 0, req, 5, hostBytes.size)
                IpPackets.putU16(req, 5 + hostBytes.size, dstPort)
                out.write(req); out.flush()
                val rep = readExact(inp, 4)
                if (rep[1].toInt() != 0x00) throw IOException("SOCKS5 connect status=${rep[1].toInt() and 0xFF}")
                when (rep[3].toInt() and 0xFF) {
                    0x01 -> readExact(inp, 6)
                    0x04 -> readExact(inp, 18)
                    0x03 -> { val dlen = readExact(inp, 1)[0].toInt() and 0xFF; readExact(inp, dlen + 2) }
                }
            } else {
                val req = StringBuilder("CONNECT $dstHost:$dstPort HTTP/1.1\r\nHost: $dstHost:$dstPort\r\n")
                if (relay.username.isNotEmpty() || relay.password.isNotEmpty()) {
                    val token = java.util.Base64.getEncoder().encodeToString("${relay.username}:${relay.password}".toByteArray(Charsets.UTF_8))
                    req.append("Proxy-Authorization: Basic $token\r\n")
                }
                req.append("\r\n")
                out.write(req.toString().toByteArray(Charsets.US_ASCII)); out.flush()
                val statusLine = readHttpLine(inp)
                val code = statusLine.split(' ').getOrNull(1)?.toIntOrNull() ?: 0
                while (readHttpLine(inp).isNotEmpty()) {}
                if (code !in 200..299) throw IOException("Relay CONNECT HTTP $code")
            }
            return TcpSocketChannel(s)
        } catch (t: Throwable) {
            runCatching { raw.close() }
            throw t
        }
    }

    private fun openDirectHappyEyeballs(addrs: List<InetAddress>, dstPort: Int, startIdx: Int = 0): UpstreamChannel {
        if (addrs.isEmpty()) throw IOException("Çözümlenen hedef adresi yok")
        var lastErr: IOException? = null
        for (i in addrs.indices) {
            val addr = addrs[(startIdx + i) % addrs.size]
            val s = Socket()
            try {
                s.tcpNoDelay = true
                runCatching { s.receiveBufferSize = 65536; s.sendBufferSize = 65536 }
                s.connect(InetSocketAddress(addr, dstPort), 4200)
                s.soTimeout = 30_000
                return TcpSocketChannel(s)
            } catch (e: IOException) {
                runCatching { s.close() }
                lastErr = e
            }
        }
        throw lastErr ?: IOException("Hedefe bağlanılamadı")
    }

    private fun openUpstream(dstHost: String, dstPort: Int, candidateShift: Int = 0): Pair<UpstreamChannel, Boolean> {
        val literalLoopback = forceDirectForLoopback && isLiteralLoopback(dstHost)
        if (!literalLoopback) {
            // Bug #24: zero local DNS queries and fail-closed on invalid/missing custom relay
            if (routeMode == WindowsRouteMode.CUSTOM_RELAY) {
                val relay = activeRelay ?: throw IOException("Özel röle URI geçersiz veya yapılandırılmamış")
                return openExitRelay(relay, dstHost, dstPort) to true
            }
            // Bug #22: block outbound DNS/TCP until WARP registration/handshake settles or falls back
            if (routeMode == WindowsRouteMode.AUTO_WARP) {
                warpReadyLatch?.await(3800, TimeUnit.MILLISECONDS)
                if (!running.get()) throw IOException("Yerel proxy kapatıldı")
                activeRelay?.let { relay ->
                    return openExitRelay(relay, dstHost, dstPort) to true
                }
            }
        }
        val resolved = resolveTargetIps(dstHost)
        val isLoopback = forceDirectForLoopback && isLoopbackDest(dstHost, resolved)
        if (!isLoopback) {
            val relay = activeRelay
            if (relay != null) {
                return openExitRelay(relay, dstHost, dstPort) to true
            }
            val stack = warpStack
            val wt = warpTunnel
            if (stack != null && wt != null && wt.established) {
                val v4 = resolved.firstOrNull { it is Inet4Address } as? Inet4Address
                if (v4 != null) {
                    val dstInt = IpPackets.u32(v4.address, 0).toInt()
                    val ws = stack.connect(dstInt, dstPort, 5500)
                    warpFlows.incrementAndGet()
                    return UserspaceChannel(ws) to true
                }
            }
        }
        return openDirectHappyEyeballs(resolved, dstPort, candidateShift) to false
    }

    private fun buildFineTlsFragments(payload: ByteArray): List<ByteArray> {
        val sni = IpPackets.findClientHelloSni(payload) ?: return IpPackets.planFirstPayload(payload, emptyList())
        val cuts = ArrayList<Int>(6)
        cuts.add(minOf(9, payload.size - 1))
        if (sni.first > 11) cuts.add(sni.first - 2)
        cuts.add(sni.first + 1)
        cuts.add(sni.first + maxOf(2, sni.second / 2))
        if (sni.first + sni.second - 1 < payload.size) cuts.add(sni.first + sni.second - 1)
        val tcpChunks = IpPackets.splitAt(payload, cuts)
        return IpPackets.fragmentTlsClientHelloRecords(payload, tcpChunks)
    }

    private fun writeDpiFirstFlight(out: OutputStream, payload: ByteArray, strategyLevel: Int) {
        val isTls = payload.size >= 5 && (payload[0].toInt() and 0xFF) == 0x16 && (payload[1].toInt() and 0xFF) == 0x03
        val chunks = if (isTls && strategyLevel >= 1) {
            buildFineTlsFragments(payload)
        } else {
            IpPackets.planFirstPayload(payload, emptyList())
        }
        if (isTls && chunks.size > 1) tlsSplit.incrementAndGet()
        if (!isTls && chunks.size > 1) httpSplit.incrementAndGet()
        for (i in chunks.indices) {
            out.write(chunks[i])
            out.flush()
            if (i < chunks.size - 1) {
                try { Thread.sleep(2L) } catch (_: InterruptedException) { break }
            }
        }
    }

    private fun readCompleteFirstFlight(inp: InputStream, initial: ByteArray = ByteArray(0)): ByteArray {
        val acc = ByteArrayOutputStream()
        if (initial.isNotEmpty()) acc.write(initial)
        val tmp = ByteArray(4096)
        if (acc.size() == 0) {
            val n = inp.read(tmp)
            if (n <= 0) return ByteArray(0)
            acc.write(tmp, 0, n)
        }
        var cur = acc.toByteArray()
        if (cur.size >= 5 && (cur[0].toInt() and 0xFF) == 0x16 && (cur[1].toInt() and 0xFF) == 0x03) {
            val need = 5 + IpPackets.u16(cur, 3)
            while (acc.size() < need && need <= 16389) {
                val n = inp.read(tmp)
                if (n <= 0) break
                acc.write(tmp, 0, n)
            }
            cur = acc.toByteArray()
        }
        return cur
    }

    private fun bridgeBidirectional(
        clientSock: Socket,
        clientIn: InputStream,
        clientOut: OutputStream,
        upstream: UpstreamChannel,
        stripAltSvc: Boolean = false,
    ) {
        clientSock.soTimeout = 90_000
        upstream.setSoTimeout(90_000)
        val upThread = Thread({
            val buf = ByteArray(16384)
            try {
                while (running.get()) {
                    val n = clientIn.read(buf)
                    if (n < 0) break
                    bytesUp.addAndGet(n.toLong())
                    upstream.outputStream.write(buf, 0, n)
                    upstream.outputStream.flush()
                }
            } catch (_: Throwable) {
            } finally {
                upstream.shutdownOutput()
            }
        }, "freedom-pipe-up").apply {
            isDaemon = true
            start()
        }
        val buf = ByteArray(16384)
        var firstDownChunk = true
        try {
            while (running.get()) {
                val n = upstream.inputStream.read(buf)
                if (n < 0) break
                if (firstDownChunk) {
                    firstDownChunk = false
                    if (stripAltSvc && blockQuicAndLeaks) {
                        val (cleanResp, changed) = IpPackets.stripPlainHttpAltSvc(buf.copyOf(n))
                        if (changed) {
                            leaksBlocked.incrementAndGet()
                            bytesDown.addAndGet(cleanResp.size.toLong())
                            clientOut.write(cleanResp)
                            clientOut.flush()
                            continue
                        }
                    }
                }
                bytesDown.addAndGet(n.toLong())
                clientOut.write(buf, 0, n)
                clientOut.flush()
            }
        } catch (_: Throwable) {
        } finally {
            runCatching { clientSock.shutdownOutput() }
            runCatching { upstream.close() }
            runCatching { upThread.join(1500) }
        }
    }

    private fun tunnelWithDpiRetry(
        clientSock: Socket,
        clientIn: InputStream,
        clientOut: OutputStream,
        dstHost: String,
        dstPort: Int,
        sendSuccessBanner: () -> Unit,
    ) {
        val hostKey = dstHost.lowercase(Locale.US)
        val cachedLevel = hostStrategyCache[hostKey] ?: 0
        val (firstUp, masked) = openUpstream(dstHost, dstPort, 0)
        if (masked) {
            firstUp.use {
                sendSuccessBanner()
                bridgeBidirectional(clientSock, clientIn, clientOut, firstUp)
            }
            return
        }
        sendSuccessBanner()
        val firstFlight = readCompleteFirstFlight(clientIn)
        if (firstFlight.isEmpty()) {
            firstUp.close()
            return
        }
        var currentUp: UpstreamChannel? = firstUp
        for (attempt in 0..1) {
            val strat = maxOf(cachedLevel, attempt)
            val up = currentUp ?: runCatching { openUpstream(dstHost, dstPort, attempt).first }.getOrNull() ?: return
            currentUp = null
            try {
                writeDpiFirstFlight(up.outputStream, firstFlight, strat)
                up.setSoTimeout(3800)
                val firstResp = ByteArray(16384)
                val n = try {
                    up.inputStream.read(firstResp)
                } catch (e: IOException) {
                    if (attempt == 0 && e !is SocketTimeoutException) -2 else throw e
                }
                if (n > 0) {
                    hostStrategyCache[hostKey] = strat
                    bytesDown.addAndGet(n.toLong())
                    clientOut.write(firstResp, 0, n)
                    clientOut.flush()
                    try {
                        bridgeBidirectional(clientSock, clientIn, clientOut, up)
                    } finally {
                        up.close()
                    }
                    return
                } else if (n == -1 && attempt == 1) {
                    up.close()
                    return
                } else {
                    up.close()
                    if (attempt == 0) {
                        tlsAdaptiveRetries.incrementAndGet()
                        rstDropped.incrementAndGet()
                        WindowsLogBus.append("DPI", "$dstHost için anında RST/EOF algılandı; 4-parçalı ince TLS bölme ile tekrar deneniyor")
                        continue
                    }
                    return
                }
            } catch (t: Throwable) {
                up.close()
                if (attempt == 0) {
                    tlsAdaptiveRetries.incrementAndGet()
                    if (t is IOException && t !is SocketTimeoutException) rstDropped.incrementAndGet()
                    WindowsLogBus.append("DPI", "$dstHost ilk uçuş hatası (${t.message}); 4-parçalı ince TLS bölme ile tekrar deneniyor")
                    continue
                }
                throw t
            }
        }
    }

    private fun readHttpLine(input: InputStream): String =
        IpPackets.readBoundedHttpLine(input, 8192)

    private fun readExact(input: InputStream, n: Int): ByteArray {
        val out = ByteArray(n)
        var got = 0
        while (got < n) {
            val k = input.read(out, got, n - got)
            if (k < 0) throw IOException("EOF")
            got += k
        }
        return out
    }

    private fun isBlockedDestination(host: String, port: Int): String? {
        if (blockQuicAndLeaks && IpPackets.isLeakRiskTcpPort(port)) return "STUN/IP-Discovery"
        if (blockTrackers && IpPackets.isTrackerOrAdDomain(host)) return "Tracker/Telemetry"
        return null
    }

    private fun handleClient(clientSock: Socket) {
        connections.incrementAndGet()
        clientSock.use { sock ->
            val pb = PushbackInputStream(BufferedInputStream(sock.inputStream, 16384), 16)
            val out = BufferedOutputStream(sock.outputStream)
            val b0 = pb.read()
            if (b0 < 0) return
            pb.unread(b0)
            if (b0 == 0x05) {
                handleSocks5(sock, pb, out)
            } else {
                handleHttp(sock, pb, out)
            }
        }
    }

    private fun handleSocks5(sock: Socket, inp: InputStream, out: OutputStream) {
        val hdr = readExact(inp, 2)
        if (hdr[0].toInt() != 0x05) return
        val nMethods = hdr[1].toInt() and 0xFF
        if (nMethods > 0) readExact(inp, nMethods)
        out.write(byteArrayOf(0x05, 0x00)); out.flush()

        val req = readExact(inp, 4)
        if (req[0].toInt() != 0x05) return
        val cmd = req[1].toInt() and 0xFF
        val atyp = req[3].toInt() and 0xFF
        val dstHost = when (atyp) {
            0x01 -> {
                val b = readExact(inp, 4)
                "${b[0].toInt() and 0xFF}.${b[1].toInt() and 0xFF}.${b[2].toInt() and 0xFF}.${b[3].toInt() and 0xFF}"
            }
            0x03 -> {
                val len = readExact(inp, 1)[0].toInt() and 0xFF
                String(readExact(inp, len), Charsets.US_ASCII)
            }
            0x04 -> InetAddress.getByAddress(readExact(inp, 16)).hostAddress
            else -> return
        }
        val portBytes = readExact(inp, 2)
        val dstPort = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)

        if (cmd == 0x03) {
            if (blockQuicAndLeaks) leaksBlocked.incrementAndGet()
            out.write(byteArrayOf(0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0)); out.flush()
            return
        }
        if (cmd != 0x01) {
            out.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0)); out.flush()
            return
        }
        val blocked = isBlockedDestination(dstHost, dstPort)
        if (blocked != null) {
            if (blocked == "Tracker/Telemetry") trackersBlocked.incrementAndGet() else leaksBlocked.incrementAndGet()
            out.write(byteArrayOf(0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0)); out.flush()
            return
        }
        tunnelWithDpiRetry(sock, inp, out, dstHost, dstPort) {
            out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            out.flush()
        }
    }

    private fun parseHostPort(raw: String, defaultPort: Int): Pair<String, Int>? {
        val t = raw.trim()
        if (t.isEmpty()) return null
        if (t.startsWith("[")) {
            val end = t.indexOf(']')
            if (end <= 1) return null
            val h = t.substring(1, end)
            val p = if (end + 1 < t.length && t[end + 1] == ':') t.substring(end + 2).toIntOrNull() ?: defaultPort else defaultPort
            return h to p
        }
        val colon = t.lastIndexOf(':')
        return if (colon > 0 && colon == t.indexOf(':')) {
            t.substring(0, colon) to (t.substring(colon + 1).toIntOrNull() ?: defaultPort)
        } else {
            t to defaultPort
        }
    }

    private fun handleHttp(sock: Socket, inp: InputStream, out: OutputStream) {
        val reqLine = readHttpLine(inp)
        val parts = reqLine.split(' ')
        if (parts.size < 3) return
        val method = parts[0].uppercase(Locale.US)
        val target = parts[1]
        val version = parts[2]
        val headerLines = ArrayList<String>()
        var hostHeader = ""
        while (true) {
            val line = readHttpLine(inp)
            if (line.isEmpty()) break
            if (line.startsWith("Host:", ignoreCase = true)) hostHeader = line.substring(5).trim()
            if (!line.startsWith("Proxy-Connection:", ignoreCase = true) &&
                !line.startsWith("Proxy-Authorization:", ignoreCase = true)
            ) {
                headerLines.add(line)
            }
        }
        if (method == "CONNECT") {
            val (dstHost, dstPort) = parseHostPort(target, 443) ?: return
            val blocked = isBlockedDestination(dstHost, dstPort)
            if (blocked != null) {
                if (blocked == "Tracker/Telemetry") trackersBlocked.incrementAndGet() else leaksBlocked.incrementAndGet()
                out.write("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".toByteArray(Charsets.US_ASCII))
                out.flush()
                return
            }
            tunnelWithDpiRetry(sock, inp, out, dstHost, dstPort) {
                out.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray(Charsets.US_ASCII))
                out.flush()
            }
            return
        }

        // Plain HTTP forwarding with URL tracking param stripping & DevicePersona spoofing
        var relPath = target
        var dstHost = ""
        var dstPort = 80
        if (target.startsWith("http://", ignoreCase = true)) {
            val uri = runCatching { URI(target) }.getOrNull() ?: return
            dstHost = uri.host ?: return
            dstPort = if (uri.port > 0) uri.port else 80
            val p = uri.rawPath.orEmpty().ifEmpty { "/" }
            val q = uri.rawQuery?.let { "?$it" }.orEmpty()
            relPath = "$p$q"
        } else {
            val hp = parseHostPort(hostHeader, 80) ?: return
            dstHost = hp.first
            dstPort = hp.second
        }
        val blocked = isBlockedDestination(dstHost, dstPort)
        if (blocked != null) {
            if (blocked == "Tracker/Telemetry") trackersBlocked.incrementAndGet() else leaksBlocked.incrementAndGet()
            out.write("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".toByteArray(Charsets.US_ASCII))
            out.flush()
            return
        }
        val rawHttp = StringBuilder("$method $relPath $version\r\n")
        for (h in headerLines) rawHttp.append(h).append("\r\n")
        rawHttp.append("\r\n")
        val rawBytes = rawHttp.toString().toByteArray(Charsets.ISO_8859_1)
        val cleanRes = IpPackets.sanitizePlainHttpHeadersDetailed(
            rawBytes,
            persona = persona,
            stripGeoHeaders = persona != DevicePersona.OFF,
            stripTrackingParams = stripUrlParams,
        )
        if (cleanRes.leakBlocked) leaksBlocked.incrementAndGet()
        if (cleanRes.paramsStripped) paramsStripped.incrementAndGet()
        val clean = cleanRes.bytes
        val (up, masked) = openUpstream(dstHost, dstPort, 0)
        up.use {
            if (masked) {
                up.outputStream.write(clean)
                up.outputStream.flush()
            } else {
                writeDpiFirstFlight(up.outputStream, clean, 0)
            }
            bridgeBidirectional(sock, inp, out, up, stripAltSvc = true)
        }
    }

    override fun close() {
        if (!running.compareAndSet(true, false)) return
        localPort = 0
        warpReadyLatch?.countDown()
        runCatching { serverSocket?.close() }
        runCatching { warpStack?.close() }
        runCatching { warpTunnel?.close() }
        runCatching { internalDoh?.close() }
        runCatching { acceptThread?.interrupt() }
        ioPool.shutdownNow()
        WindowsLogBus.append("Proxy", "Yerel motor durduruldu")
    }
}

private fun runCliSelfTest(): Int {
    check(Native.available) { "Native motor yüklenemedi: ${Native.loadError}" }
    check(Native.apiVersion() == Native.EXPECTED_API) { "API sürüm uyuşmazlığı: ${Native.apiVersion()}" }
    val rec = Record().int(1, 2026L).text(2, "freedom-self-test")
    val round = Wire.decode(Wire.encode(rec))
    check(round == rec) { "Wire codec roundtrip uyuşmadı" }
    FreedomIconId.entries.forEach { id ->
        val cmds = FreedomIconPaths.commands(id)
        check(cmds.isNotEmpty()) { "Eksik SVG yolu: $id" }
        val p2d = SwingVectorIcons.toPath2D(id)
        check(!p2d.bounds2D.isEmpty) { "Boş Path2D: $id" }
    }
    val cf = GlobalCensorshipTelemetry.parseCloudflareTrace("ip=198.51.100.7\nloc=TR\nwarp=plus\ncolo=IST\nsni=plaintext\nhttp=http/2")
    val ripe = GlobalCensorshipTelemetry.parseRipeAtlasJson("""{"count":12,"results":[{"asn_v4":9121},{"asn_v4":34984}]}""", "TR", 42)
    val ooni = GlobalCensorshipTelemetry.parseOoniJson("""{"results":[{"probe_cc":"TR","probe_asn":"AS9121","test_name":"web_connectivity","input":"https://discord.com","anomaly":true,"confirmed":true}]}""")
    val mlab = GlobalCensorshipTelemetry.parseMlabLocateJson("""{"results":[{"machine":"ndt-mlab1-ist01.mlab-oti.measurement-lab.org","city":"Istanbul","country":"TR"}]}""", 31)
    check(cf.ok && cf.warp == "plus" && ripe.connectedCount == 12 && ooni.size == 1 && mlab.site == "ist01") {
        "Telemetri ayrıştırıcı kontrolü başarısız"
    }
    val telReport = Text.telemetryReport(GlobalTelemetrySnapshot(1L, ripe, ooni, 15L, true, "", mlab, cf))
    check("RIPE Atlas" in telReport && "OONI" in telReport) { "Telemetri raporu eksik" }
    val httpResp = "HTTP/1.1 200 OK\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nContent-Length: 2\r\n\r\nOK".toByteArray(Charsets.US_ASCII)
    val (stripped, changed) = IpPackets.stripPlainHttpAltSvc(httpResp)
    check(changed && !"alt-svc".let { String(stripped, Charsets.US_ASCII).lowercase(Locale.US).contains("h3=") }) {
        "Alt-Svc: h3 temizlenmedi"
    }
    val (sanEnable, sanServer) = WindowsSystemProxy.sanitizeCapturedProxy(1, "127.0.0.1:54321")
    check(sanEnable == 0 && sanServer == null) { "Çökmüş sistem vekili temizlenmedi" }
    DiagnosticSession().use { s ->
        val ps = s.startProxy(DesyncConfig(mode = DesyncMode.REALITY_VISION, port = 0))
        check(ps.active && ps.port > 0) { "Native REALITY_VISION proxy başlatılamadı" }
        s.stopProxy()
    }
    WindowsNextGenProxy(port = 0, routeMode = WindowsRouteMode.HYBRID_DPI, preferredDesyncMode = DesyncMode.REALITY_VISION).use { p ->
        val bPort = p.start()
        check(bPort > 0 && p.statusSnapshot().mode == DesyncMode.REALITY_VISION) { "WindowsNextGenProxy self-test port=$bPort" }
    }
    println("SELF-TEST PASSED · Native ${Native.engineVersion()} · Icons=${FreedomIconId.entries.size} · Telemetry & Proxy OK")
    return 0
}

/** Headless mode: `FreedomNetwork --cli example.com [--dns 1.1.1.1] [--alt 9.9.9.9]`. */
fun runCli(args: List<String>): Int {
    val targets = ArrayList<String>()
    val dns = ArrayList<String>()
    val alt = ArrayList<String>()
    val doh = ArrayList<String>()
    var system = false
    var serve = false
    var selfTest = false
    var routeMode = WindowsRouteMode.AUTO_WARP
    var relayUri = ""
    var desyncMode = DesyncMode.OFF
    var proxyPort = -1
    var persona = DevicePersona.IPHONE_19_BETA
    var blockTrackers = true
    var stripUrlParams = true
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--help", "-h" -> {
                println("Freedom Network CLI ${runCatching { Native.engineVersion() }.getOrElse { "native" }}")
                println("Kullanım: FreedomNetwork --cli [hedef ...] [--dns IP] [--alt IP] [--doh URL]")
                println("          [--mode warp|hybrid|relay] [--relay URI] [--proxy PORT] [--serve] [--self-test]")
                println("          [--desync reality|split|disorder|badsum|ttl|quic|adaptive]")
                println("          [--persona iphone19|android19|pixel14|off] [--no-trackers] [--no-strip] [--system]")
                return 0
            }
            "--cli" -> {}
            "--self-test" -> selfTest = true
            "--dns" -> dns += args.getOrNull(++i) ?: ""
            "--alt" -> alt += args.getOrNull(++i) ?: ""
            "--doh" -> doh += args.getOrNull(++i) ?: ""
            "--system" -> system = true
            "--serve" -> serve = true
            "--mode" -> {
                val m = (args.getOrNull(++i) ?: "warp").lowercase(Locale.US)
                routeMode = when (m) {
                    "hybrid", "dpi" -> WindowsRouteMode.HYBRID_DPI
                    "relay", "tor" -> WindowsRouteMode.CUSTOM_RELAY
                    else -> WindowsRouteMode.AUTO_WARP
                }
            }
            "--relay" -> {
                relayUri = args.getOrNull(++i) ?: ""
                if (relayUri.isNotBlank()) routeMode = WindowsRouteMode.CUSTOM_RELAY
            }
            "--no-trackers" -> blockTrackers = false
            "--no-strip" -> stripUrlParams = false
            "--persona" -> {
                val p = (args.getOrNull(++i) ?: "iphone19").lowercase(Locale.US)
                persona = when (p) {
                    "off", "0", "none" -> DevicePersona.OFF
                    "android", "android19" -> DevicePersona.ANDROID_19_QUANTUM
                    "pixel", "pixel14" -> DevicePersona.PIXEL_14_FUTURE
                    else -> DevicePersona.IPHONE_19_BETA
                }
            }
            "--desync" -> {
                val m = (args.getOrNull(++i) ?: "reality").lowercase(Locale.US)
                desyncMode = when (m) {
                    "split", "1" -> DesyncMode.SPLIT
                    "disorder", "2" -> DesyncMode.DISORDER
                    "badsum", "3" -> DesyncMode.FAKE_BAD_SUM
                    "ttl", "autottl", "4" -> DesyncMode.FAKE_AUTO_TTL
                    "quic", "5" -> DesyncMode.QUIC_SCRAMBLE
                    "adaptive", "6" -> DesyncMode.ADAPTIVE_FULL
                    else -> DesyncMode.REALITY_VISION
                }
            }
            "--proxy" -> proxyPort = (args.getOrNull(++i) ?: "8880").toIntOrNull() ?: 8880
            else -> targets += args[i]
        }
        i++
    }
    if (selfTest) {
        return try {
            runCliSelfTest()
        } catch (t: Throwable) {
            System.err.println("SELF-TEST FAILED: ${t.message}")
            1
        }
    }
    return try {
        DiagnosticSession().use { session ->
            val env = WindowsPlatform.environment(dns.filter { it.isNotEmpty() })
            session.setEnvironment(env)
            println("Freedom Network ${Native.engineVersion()} · TLS güveni: ${WindowsPlatform.trust.second}")
            print(Text.environment(env))
            println()
            if (targets.isNotEmpty()) {
                val report = session.run(
                    targets, alt.filter { it.isNotEmpty() }, WindowsPlatform.prober(),
                    WindowsPlatform.dohClient(), doh.filter { it.isNotEmpty() },
                )
                print(Text.report(report))
            }
            if (desyncMode != DesyncMode.OFF || proxyPort >= 0 || serve) {
                val bindPort = if (proxyPort >= 0) proxyPort else 8880
                val effectiveDesync = if (desyncMode != DesyncMode.OFF) desyncMode else DesyncMode.REALITY_VISION
                WindowsNextGenProxy(
                    port = bindPort,
                    routeMode = routeMode,
                    customRelayUri = relayUri,
                    persona = persona,
                    blockTrackers = blockTrackers,
                    stripUrlParams = stripUrlParams,
                    preferredDesyncMode = effectiveDesync,
                ).use { proxy ->
                    val bound = proxy.start()
                    println()
                    println("FREEDOM NETWORK (YENİ NESİL VEKİL): 127.0.0.1:$bound · Rota: ${proxy.routeLabel} · Strateji: ${Text.desyncMode(effectiveDesync)}")
                    if (serve) {
                        println("Vekil çalışıyor (çıkmak için Ctrl+C)...")
                        while (!Thread.currentThread().isInterrupted) {
                            try { Thread.sleep(1000) } catch (_: InterruptedException) { break }
                        }
                    }
                }
            }
            if (system) {
                println()
                print(Text.system(SystemSnapshot.capture()))
            }
            0
        }
    } catch (e: NativeException) {
        System.err.println(e.message)
        2
    }
}

// Swing Vector Icon Renderer (Pure Java2D Path2D - Embedded 24x24 Lucide SVG Path Engine + Freedom Emblem)
internal object SwingVectorIcons {
    private val pathCache = ConcurrentHashMap<FreedomIconId, Path2D.Double>()

    private val freedomOuterShield = Path2D.Float().apply {
        moveTo(12f, 1.8f)
        lineTo(20.6f, 5.2f)
        lineTo(19.4f, 13.8f)
        lineTo(12f, 22.2f)
        lineTo(4.6f, 13.8f)
        lineTo(3.4f, 5.2f)
        closePath()
    }

    private val freedomInnerCore = Path2D.Float().apply {
        moveTo(12f, 4.4f)
        lineTo(17.9f, 6.8f)
        lineTo(17.0f, 13.0f)
        lineTo(12f, 19.2f)
        lineTo(7.0f, 13.0f)
        lineTo(6.1f, 6.8f)
        closePath()
    }

    private val freedomUpperWing = Path2D.Float().apply {
        moveTo(7.8f, 11.4f)
        lineTo(12f, 7.2f)
        lineTo(16.2f, 11.4f)
    }

    private val freedomLowerWing = Path2D.Float().apply {
        moveTo(8.8f, 14.4f)
        lineTo(12f, 11.2f)
        lineTo(15.2f, 14.4f)
    }

    private val powerArc = Arc2D.Float(4f, 4f, 16f, 16f, 145f, 250f, Arc2D.OPEN)

    fun toPath2D(id: FreedomIconId): Path2D.Double = pathCache.computeIfAbsent(id) { key ->
        Path2D.Double(Path2D.WIND_NON_ZERO).apply {
            for (cmd in FreedomIconPaths.commands(key)) {
                when (cmd) {
                    is SvgCmd.MoveTo -> moveTo(cmd.x.toDouble(), cmd.y.toDouble())
                    is SvgCmd.LineTo -> lineTo(cmd.x.toDouble(), cmd.y.toDouble())
                    is SvgCmd.QuadTo -> quadTo(cmd.cx.toDouble(), cmd.cy.toDouble(), cmd.x.toDouble(), cmd.y.toDouble())
                    is SvgCmd.CubicTo -> curveTo(
                        cmd.c1x.toDouble(), cmd.c1y.toDouble(),
                        cmd.c2x.toDouble(), cmd.c2y.toDouble(),
                        cmd.x.toDouble(), cmd.y.toDouble(),
                    )
                    SvgCmd.Close -> closePath()
                }
            }
        }
    }

    private inline fun withMatrix(g2: Graphics2D, cx: Int, cy: Int, size: Int, block: () -> Unit) {
        val oldTransform = g2.transform
        val oldStroke = g2.stroke
        val oldAa = g2.getRenderingHint(RenderingHints.KEY_ANTIALIASING)
        val oldStrokeCtrl = g2.getRenderingHint(RenderingHints.KEY_STROKE_CONTROL)
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        g2.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE)
        g2.translate(cx.toDouble(), cy.toDouble())
        val s = size.toDouble() / 24.0
        g2.scale(s, s)
        g2.translate(-12.0, -12.0)
        block()
        g2.transform = oldTransform
        g2.stroke = oldStroke
        if (oldAa != null) g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, oldAa)
        if (oldStrokeCtrl != null) g2.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, oldStrokeCtrl)
    }

    fun drawIcon(
        g2: Graphics2D,
        id: FreedomIconId,
        cx: Int,
        cy: Int,
        size: Int,
        color: Color,
        strokeWidth: Float = 1.9f,
        fillColor: Color? = null,
    ) {
        val p = toPath2D(id)
        withMatrix(g2, cx, cy, size) {
            if (fillColor != null && fillColor.alpha > 0) {
                g2.color = fillColor
                g2.fill(p)
            }
            val minLogicalStroke = (1.85f * 24f / size.coerceAtLeast(8)).coerceAtMost(strokeWidth * 1.45f)
            g2.color = color
            g2.stroke = BasicStroke(maxOf(strokeWidth, minLogicalStroke), BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
            g2.draw(p)
        }
    }

    fun asSwingIcon(
        id: FreedomIconId,
        size: Int = 15,
        color: Color = Color(226, 232, 240),
        strokeWidth: Float = 1.9f,
    ): Icon = object : Icon {
        override fun getIconWidth(): Int = size
        override fun getIconHeight(): Int = size
        override fun paintIcon(c: java.awt.Component?, g: Graphics, x: Int, y: Int) {
            val g2 = g.create() as Graphics2D
            drawIcon(g2, id, x + size / 2, y + size / 2, size, color, strokeWidth)
            g2.dispose()
        }
    }

    fun drawFreedomShieldEmblem(g2: Graphics2D, cx: Int, cy: Int, size: Int, primary: Color, accent: Color) {
        withMatrix(g2, cx, cy, size) {
            g2.color = Color(primary.red, primary.green, primary.blue, 46)
            g2.fill(freedomOuterShield)
            g2.color = Color(accent.red, accent.green, accent.blue, 62)
            g2.fill(freedomInnerCore)
            g2.color = primary
            g2.stroke = BasicStroke(1.9f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
            g2.draw(freedomOuterShield)
            g2.color = accent
            g2.stroke = BasicStroke(2.2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
            g2.draw(freedomUpperWing)
            g2.color = Color.WHITE
            g2.stroke = BasicStroke(2.0f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
            g2.draw(freedomLowerWing)
        }
    }

    fun drawShield(g2: Graphics2D, cx: Int, cy: Int, size: Int, color: Color, fill: Boolean = true) =
        drawIcon(
            g2,
            FreedomIconId.SHIELD_CHECK,
            cx,
            cy,
            size,
            color,
            strokeWidth = 2f,
            fillColor = if (fill) Color(color.red, color.green, color.blue, 38) else null,
        )

    fun drawBolt(g2: Graphics2D, cx: Int, cy: Int, size: Int, color: Color) =
        drawIcon(
            g2,
            FreedomIconId.ZAP,
            cx,
            cy,
            size,
            color,
            strokeWidth = 2f,
            fillColor = Color(color.red, color.green, color.blue, 45),
        )

    fun drawLock(g2: Graphics2D, cx: Int, cy: Int, size: Int, color: Color) =
        drawIcon(
            g2,
            FreedomIconId.LOCK,
            cx,
            cy,
            size,
            color,
            strokeWidth = 2f,
            fillColor = Color(color.red, color.green, color.blue, 35),
        )

    fun drawRadar(g2: Graphics2D, cx: Int, cy: Int, size: Int, color: Color) =
        drawIcon(
            g2,
            FreedomIconId.RADAR,
            cx,
            cy,
            size,
            color,
            strokeWidth = 1.9f,
            fillColor = Color(color.red, color.green, color.blue, 30),
        )

    fun drawGlobe(g2: Graphics2D, cx: Int, cy: Int, size: Int, color: Color) =
        drawIcon(g2, FreedomIconId.GLOBE, cx, cy, size, color, strokeWidth = 2f)

    fun drawPulse(g2: Graphics2D, cx: Int, cy: Int, size: Int, color: Color) =
        drawIcon(g2, FreedomIconId.ACTIVITY, cx, cy, size, color, strokeWidth = 2.2f)

    fun drawPower(g2: Graphics2D, cx: Int, cy: Int, size: Int, color: Color) {
        withMatrix(g2, cx, cy, size) {
            g2.color = color
            g2.stroke = BasicStroke(2.5f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
            g2.draw(powerArc)
            g2.draw(Line2D.Float(12f, 3f, 12f, 11f))
        }
    }

    fun drawTerminal(g2: Graphics2D, cx: Int, cy: Int, size: Int, color: Color) =
        drawIcon(g2, FreedomIconId.TERMINAL, cx, cy, size, color, strokeWidth = 2f)

    fun drawCopy(g2: Graphics2D, cx: Int, cy: Int, size: Int, color: Color) =
        drawIcon(g2, FreedomIconId.COPY, cx, cy, size, color, strokeWidth = 2f)

    fun drawCheck(g2: Graphics2D, cx: Int, cy: Int, size: Int, color: Color) =
        drawIcon(g2, FreedomIconId.CHECK_CIRCLE, cx, cy, size, color, strokeWidth = 2.2f)
}

/**
 * ModernPowerShieldPanel:
 * High-contrast Freedom Network Hero Control Disc for Windows Swing with visibility-aware animator,
 * connecting state, rotating orbital reticle, 12 azimuth precision ticks, and faceted Freedom Shield emblem.
 */
class ModernPowerShieldPanel : JPanel() {
    var isActive = false
        set(value) {
            if (field != value) {
                field = value
                syncAnimator()
                repaint()
            }
        }
    var isConnecting = false
        set(value) {
            if (field != value) {
                field = value
                syncAnimator()
                repaint()
            }
        }
    var portInfo: String = ""
        set(value) {
            field = value
            repaint()
        }
    var onToggleListener: (() -> Unit)? = null

    private var animPhase = 0f
    private var isHovered = false
    private var windowMinimized = false
    private val animTimer = Timer(33) {
        animPhase = (animPhase + 0.015f) % 1.0f
        repaint()
    }

    init {
        preferredSize = Dimension(650, 178)
        background = Color(7, 11, 20)
        cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)

        addHierarchyListener { e ->
            if ((e.changeFlags and HierarchyEvent.SHOWING_CHANGED.toLong()) != 0L) {
                syncAnimator()
            }
        }

        addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                val cx = width / 2
                val cy = height / 2
                val btnR = (minOf(cx, cy) * 0.62).toInt()
                val dx = e.x - cx
                val dy = e.y - cy
                if (dx * dx + dy * dy <= (btnR * 1.3) * (btnR * 1.3)) {
                    onToggleListener?.invoke()
                }
            }
            override fun mouseEntered(e: MouseEvent) {
                isHovered = true
                repaint()
            }
            override fun mouseExited(e: MouseEvent) {
                isHovered = false
                repaint()
            }
        })
    }

    fun setWindowMinimized(minimized: Boolean) {
        if (windowMinimized != minimized) {
            windowMinimized = minimized
            syncAnimator()
        }
    }

    private fun syncAnimator() {
        val shouldRun = !windowMinimized && isShowing && (isActive || isConnecting)
        if (shouldRun) {
            if (!animTimer.isRunning) animTimer.start()
        } else {
            if (animTimer.isRunning) animTimer.stop()
        }
    }

    override fun addNotify() {
        super.addNotify()
        syncAnimator()
    }

    override fun removeNotify() {
        animTimer.stop()
        super.removeNotify()
    }

    fun stop() {
        animTimer.stop()
    }

    override fun paintComponent(g: Graphics) {
        super.paintComponent(g)
        val g2 = g.create() as Graphics2D
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON)
        g2.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE)

        val cx = width / 2
        val cy = height / 2
        val maxR = minOf(cx, cy) - 10
        if (maxR <= 0) {
            g2.dispose()
            return
        }

        val btnR = (maxR * 0.60).toInt()
        val primary = when {
            isActive -> Color(16, 185, 129)
            isConnecting -> Color(245, 158, 11)
            else -> Color(56, 189, 248)
        }
        val accent = when {
            isActive -> Color(34, 211, 238)
            isConnecting -> Color(251, 191, 36)
            else -> Color(129, 140, 248)
        }

        // 1) Expanding cyber pulse waves when active or connecting
        if (isActive || isConnecting) {
            val waveCount = 3
            for (i in 0 until waveCount) {
                val phase = (animPhase + i * (1f / waveCount)) % 1f
                val ringR = (btnR * 1.06 + phase * (maxR - btnR * 1.06)).toInt()
                val alpha = ((1.0f - phase) * 140).toInt().coerceIn(0, 255)
                g2.color = Color(primary.red, primary.green, primary.blue, alpha)
                g2.stroke = BasicStroke((2.4f - phase * 1.2f).coerceAtLeast(1.0f))
                g2.drawOval(cx - ringR, cy - ringR, ringR * 2, ringR * 2)
            }
        } else {
            val ringR = (btnR * 1.13).toInt()
            g2.color = Color(primary.red, primary.green, primary.blue, 50)
            g2.stroke = BasicStroke(1.4f)
            g2.drawOval(cx - ringR, cy - ringR, ringR * 2, ringR * 2)
        }

        // 2) Counter-rotating orbital dashed reticles
        val reticleR = (btnR * 1.13).toInt()
        g2.color = Color(primary.red, primary.green, primary.blue, if (isActive || isConnecting) 170 else 90)
        g2.stroke = BasicStroke(2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND, 10f, floatArrayOf(10f, 7f), animPhase * 360f)
        g2.drawOval(cx - reticleR, cy - reticleR, reticleR * 2, reticleR * 2)

        val outerReticleR = (btnR * 1.23).toInt()
        g2.color = Color(accent.red, accent.green, accent.blue, if (isActive || isConnecting) 110 else 50)
        g2.stroke = BasicStroke(1.4f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND, 10f, floatArrayOf(4f, 9f), -animPhase * 252f)
        g2.drawOval(cx - outerReticleR, cy - outerReticleR, outerReticleR * 2, outerReticleR * 2)

        // 3) Ambient radial aura
        val auraR = (btnR * 1.42).toInt()
        g2.paint = RadialGradientPaint(
            java.awt.geom.Point2D.Float(cx.toFloat(), cy.toFloat()),
            auraR.toFloat(),
            floatArrayOf(0f, 1f),
            arrayOf(
                Color(
                    primary.red,
                    primary.green,
                    primary.blue,
                    when {
                        isActive -> if (isHovered) 115 else 90
                        isConnecting -> 80
                        else -> 38
                    },
                ),
                Color(7, 11, 20, 0),
            ),
        )
        g2.fillOval(cx - auraR, cy - auraR, auraR * 2, auraR * 2)

        // 4) Center disc fill
        val p1 = java.awt.geom.Point2D.Float((cx - btnR * 0.4f).toFloat(), (cy - btnR).toFloat())
        val p2 = java.awt.geom.Point2D.Float((cx + btnR * 0.4f).toFloat(), (cy + btnR).toFloat())
        g2.paint = when {
            isActive -> LinearGradientPaint(p1, p2, floatArrayOf(0f, 1f), arrayOf(Color(4, 47, 46), Color(6, 95, 70)))
            isConnecting -> LinearGradientPaint(p1, p2, floatArrayOf(0f, 1f), arrayOf(Color(30, 27, 75), Color(15, 23, 42)))
            else -> LinearGradientPaint(p1, p2, floatArrayOf(0f, 1f), arrayOf(Color(10, 18, 34), Color(19, 32, 56)))
        }
        g2.fillOval(cx - btnR, cy - btnR, btnR * 2, btnR * 2)

        // Azimuth 12 precision ticks
        g2.color = Color(226, 232, 240, if (isActive) 75 else 45)
        g2.stroke = BasicStroke(1.2f)
        for (tick in 0 until 12) {
            val rad = Math.toRadians(tick * 30.0)
            val cosA = kotlin.math.cos(rad)
            val sinA = kotlin.math.sin(rad)
            g2.drawLine(
                (cx + cosA * btnR * 0.87).toInt(),
                (cy + sinA * btnR * 0.87).toInt(),
                (cx + cosA * btnR * 0.93).toInt(),
                (cy + sinA * btnR * 0.93).toInt(),
            )
        }

        // Glowing rim border
        g2.paint = LinearGradientPaint(p1, p2, floatArrayOf(0f, 0.5f, 1f), arrayOf(primary, accent, primary))
        g2.stroke = BasicStroke(if (isActive || isConnecting) 2.8f else (if (isHovered) 2.4f else 2.0f))
        g2.drawOval(cx - btnR, cy - btnR, btnR * 2, btnR * 2)

        // Top-center Freedom Shield Emblem badge
        val badgeCx = cx
        val badgeCy = cy - (btnR * 0.25).toInt()
        val badgeR = (btnR * 0.30).toInt()
        g2.color = Color(primary.red, primary.green, primary.blue, if (isActive || isConnecting) 65 else 40)
        g2.fillOval(badgeCx - badgeR, badgeCy - badgeR, badgeR * 2, badgeR * 2)
        g2.color = Color(primary.red, primary.green, primary.blue, 130)
        g2.stroke = BasicStroke(1.2f)
        g2.drawOval(badgeCx - badgeR, badgeCy - badgeR, badgeR * 2, badgeR * 2)
        SwingVectorIcons.drawFreedomShieldEmblem(
            g2, badgeCx, badgeCy, (badgeR * 1.45).toInt(),
            when {
                isActive -> Color(52, 211, 153)
                isConnecting -> Color(251, 191, 36)
                else -> Color(56, 189, 248)
            },
            when {
                isActive -> Color(34, 211, 238)
                isConnecting -> Color(253, 230, 138)
                else -> Color(125, 211, 252)
            },
        )

        // Hero title
        g2.font = Font("Segoe UI", Font.BOLD, 12)
        val titleStr = when {
            isActive -> "KORUMA AKTİF"
            isConnecting -> "BAĞLANIYOR..."
            else -> "DOKUN VE BAĞLAN"
        }
        val fmTitle = g2.fontMetrics
        g2.color = Color.WHITE
        g2.drawString(titleStr, cx - fmTitle.stringWidth(titleStr) / 2, cy + (btnR * 0.27).toInt())

        // Inner status pill
        g2.font = Font("Segoe UI", Font.BOLD, 9)
        val subStr = when {
            isActive -> portInfo.ifEmpty { "SİSTEM KORUMALI" }
            isConnecting -> "WARP / RÖLE EL SIKIŞMASI"
            else -> "AĞ KORUMASI HAZIR"
        }
        val fmSub = g2.fontMetrics
        val pillW = fmSub.stringWidth(subStr) + 18
        val pillH = 16
        val pillX = cx - pillW / 2
        val pillY = cy + (btnR * 0.42).toInt()
        g2.color = when {
            isActive -> Color(6, 78, 59, 175)
            isConnecting -> Color(69, 26, 3, 185)
            else -> Color(15, 23, 42, 185)
        }
        g2.fillRoundRect(pillX, pillY, pillW, pillH, pillH, pillH)
        g2.color = when {
            isActive -> Color(52, 211, 153, 180)
            isConnecting -> Color(251, 191, 36, 180)
            else -> Color(56, 189, 248, 120)
        }
        g2.stroke = BasicStroke(1f)
        g2.drawRoundRect(pillX, pillY, pillW, pillH, pillH, pillH)
        g2.color = when {
            isActive -> Color(167, 243, 208)
            isConnecting -> Color(253, 230, 138)
            else -> Color(147, 197, 253)
        }
        g2.drawString(subStr, cx - fmSub.stringWidth(subStr) / 2, pillY + ((pillH - fmSub.height) / 2) + fmSub.ascent)

        g2.dispose()
    }
}

typealias AnimatedPulsePanel = ModernPowerShieldPanel

/**
 * ThroughputSparklinePanel:
 * Real-time network speed & throughput waveform graph in Swing Java2D using Catmull-Rom cubic
 * Bezier splines, dual RX/TX gradient fills, dynamic B/s..GB/s scaling, and 24x24 Lucide SVG arrows.
 */
class ThroughputSparklinePanel : JPanel() {
    private val maxSamples = 32
    private val rxHistory = FloatArray(maxSamples)
    private val txHistory = FloatArray(maxSamples)
    private val ptsX = DoubleArray(maxSamples)
    private val rxPtsY = DoubleArray(maxSamples)
    private val txPtsY = DoubleArray(maxSamples)
    private var writeIdx = 0
    private var currentRxKbps = 0f
    private var currentTxKbps = 0f
    private var totalRxBytes = 0L
    private var totalTxBytes = 0L

    init {
        preferredSize = Dimension(650, 80)
        background = Color(10, 16, 29)
        border = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color(30, 41, 59), 1),
            BorderFactory.createEmptyBorder(6, 10, 6, 10),
        )
    }

    internal fun formatRate(kbps: Float): String {
        val safe = if (kbps.isFinite() && kbps >= 0f) kbps else 0f
        val bps = safe * 1024f
        return when {
            bps < 1024f -> "%.0f B/s".format(Locale.US, bps)
            safe < 1024f -> "%.1f KB/s".format(Locale.US, safe)
            safe < 1024f * 1024f -> "%.2f MB/s".format(Locale.US, safe / 1024f)
            else -> "%.2f GB/s".format(Locale.US, safe / (1024f * 1024f))
        }
    }

    internal fun formatBytes(bytes: Long): String {
        val b = bytes.coerceAtLeast(0L)
        return when {
            b < 1024L -> "$b B"
            b < 1024L * 1024L -> "%.1f KB".format(Locale.US, b / 1024.0)
            b < 1024L * 1024L * 1024L -> "%.2f MB".format(Locale.US, b / (1024.0 * 1024.0))
            else -> "%.2f GB".format(Locale.US, b / (1024.0 * 1024.0 * 1024.0))
        }
    }

    fun updateMetrics(rxKbps: Float, txKbps: Float, totalRx: Long, totalTx: Long) {
        currentRxKbps = rxKbps
        currentTxKbps = txKbps
        totalRxBytes = totalRx.coerceAtLeast(0L)
        totalTxBytes = totalTx.coerceAtLeast(0L)
        rxHistory[writeIdx] = rxKbps
        txHistory[writeIdx] = txKbps
        writeIdx = (writeIdx + 1) % maxSamples
        repaint()
    }

    private fun buildCatmullRom(ys: DoubleArray, stroke: Path2D.Double, area: Path2D.Double, graphTop: Double, graphBottom: Double) {
        stroke.moveTo(ptsX[0], ys[0])
        area.moveTo(ptsX[0], graphBottom)
        area.lineTo(ptsX[0], ys[0])
        val alpha = 1.0 / 6.0
        for (i in 0 until maxSamples - 1) {
            val i0 = if (i > 0) i - 1 else 0
            val i1 = i
            val i2 = i + 1
            val i3 = if (i + 2 < maxSamples) i + 2 else maxSamples - 1
            val c1x = ptsX[i1] + (ptsX[i2] - ptsX[i0]) * alpha
            val c1y = (ys[i1] + (ys[i2] - ys[i0]) * alpha).coerceIn(graphTop, graphBottom)
            val c2x = ptsX[i2] - (ptsX[i3] - ptsX[i1]) * alpha
            val c2y = (ys[i2] - (ys[i3] - ys[i1]) * alpha).coerceIn(graphTop, graphBottom)
            stroke.curveTo(c1x, c1y, c2x, c2y, ptsX[i2], ys[i2])
            area.curveTo(c1x, c1y, c2x, c2y, ptsX[i2], ys[i2])
        }
        area.lineTo(ptsX[maxSamples - 1], graphBottom)
        area.closePath()
    }

    override fun paintComponent(g: Graphics) {
        super.paintComponent(g)
        val g2 = g.create() as Graphics2D
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON)
        g2.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE)

        val w = width
        val h = height

        // Header label & vector icon (zero emoji)
        SwingVectorIcons.drawIcon(g2, FreedomIconId.ACTIVITY, 18, 14, 12, Color(148, 163, 184), 2.1f)
        g2.font = Font("Segoe UI", Font.BOLD, 10)
        g2.color = Color(148, 163, 184)
        g2.drawString("CANLI TRAFİK AKIŞI", 30, 18)

        // Speed badges with dynamic units and Lucide SVG arrows
        val rxStr = formatRate(currentRxKbps)
        val txStr = formatRate(currentTxKbps)
        val fm = g2.fontMetrics
        val txW = fm.stringWidth(txStr)
        val rxW = fm.stringWidth(rxStr)
        val txTextX = w - txW - 14
        val txArrowCx = txTextX - 8
        SwingVectorIcons.drawIcon(g2, FreedomIconId.ARROW_UP, txArrowCx, 14, 10, Color(56, 189, 248), 2.2f)
        g2.color = Color(56, 189, 248)
        g2.drawString(txStr, txTextX, 18)

        val rxTextX = txArrowCx - rxW - 16
        val rxArrowCx = rxTextX - 8
        SwingVectorIcons.drawIcon(g2, FreedomIconId.ARROW_DOWN, rxArrowCx, 14, 10, Color(16, 185, 129), 2.2f)
        g2.color = Color(16, 185, 129)
        g2.drawString(rxStr, rxTextX, 18)

        val graphTop = 26
        val graphBottom = h - 18
        val graphH = graphBottom - graphTop
        val graphLeft = 14
        val graphRight = w - 14
        val graphW = graphRight - graphLeft
        if (graphH <= 0 || graphW <= 0) {
            g2.dispose()
            return
        }

        // Horizontal midline & baseline
        g2.color = Color(30, 41, 59)
        g2.drawLine(graphLeft, graphTop + graphH / 2, graphRight, graphTop + graphH / 2)
        g2.drawLine(graphLeft, graphBottom, graphRight, graphBottom)

        var maxVal = 20f
        for (i in 0 until maxSamples) {
            if (rxHistory[i] > maxVal) maxVal = rxHistory[i]
            if (txHistory[i] > maxVal) maxVal = txHistory[i]
        }

        val stepX = graphW.toDouble() / (maxSamples - 1).toDouble()
        for (i in 0 until maxSamples) {
            val sampleIdx = (writeIdx + i) % maxSamples
            ptsX[i] = graphLeft + i * stepX
            val rxNorm = (rxHistory[sampleIdx] / maxVal).coerceIn(0f, 1f).toDouble()
            val txNorm = (txHistory[sampleIdx] / maxVal).coerceIn(0f, 1f).toDouble()
            rxPtsY[i] = graphBottom - rxNorm * (graphH * 0.9)
            txPtsY[i] = graphBottom - txNorm * (graphH * 0.9)
        }

        val rxPath = Path2D.Double()
        val txPath = Path2D.Double()
        val rxFill = Path2D.Double()
        val txFill = Path2D.Double()
        buildCatmullRom(rxPtsY, rxPath, rxFill, graphTop.toDouble(), graphBottom.toDouble())
        buildCatmullRom(txPtsY, txPath, txFill, graphTop.toDouble(), graphBottom.toDouble())

        // Dual gradient fills (TX sky cyan + RX emerald)
        val p1 = java.awt.geom.Point2D.Float(0f, graphTop.toFloat())
        val p2 = java.awt.geom.Point2D.Float(0f, graphBottom.toFloat())
        g2.paint = LinearGradientPaint(p1, p2, floatArrayOf(0f, 1f), arrayOf(Color(56, 189, 248, 42), Color(56, 189, 248, 0)))
        g2.fill(txFill)
        g2.paint = LinearGradientPaint(p1, p2, floatArrayOf(0f, 1f), arrayOf(Color(16, 185, 129, 68), Color(16, 185, 129, 0)))
        g2.fill(rxFill)

        // Draw smooth cubic splines
        g2.stroke = BasicStroke(1.6f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
        g2.color = Color(56, 189, 248)
        g2.draw(txPath)

        g2.stroke = BasicStroke(2.1f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
        g2.color = Color(16, 185, 129)
        g2.draw(rxPath)

        // Footer volume with SVG direction arrows
        g2.font = Font("Segoe UI", Font.PLAIN, 9)
        val ffm = g2.fontMetrics
        val footerBaseY = h - 4
        val footerIconCy = footerBaseY - 3
        val prefix = "Toplam Aktarım:"
        g2.color = Color(100, 116, 139)
        g2.drawString(prefix, graphLeft, footerBaseY)
        var cursorX = graphLeft + ffm.stringWidth(prefix) + 8
        SwingVectorIcons.drawIcon(g2, FreedomIconId.ARROW_UP, cursorX, footerIconCy, 9, Color(56, 189, 248), 2.0f)
        cursorX += 7
        val txVol = formatBytes(totalTxBytes)
        g2.color = Color(148, 163, 184)
        g2.drawString(txVol, cursorX, footerBaseY)
        cursorX += ffm.stringWidth(txVol) + 12
        SwingVectorIcons.drawIcon(g2, FreedomIconId.ARROW_DOWN, cursorX, footerIconCy, 9, Color(16, 185, 129), 2.0f)
        cursorX += 7
        g2.drawString(formatBytes(totalRxBytes), cursorX, footerBaseY)

        g2.dispose()
    }
}

/**
 * ModernStatCard:
 * Sleek dark glass card with custom Lucide 24x24 SVG vector icon and Segoe UI typography.
 */
class ModernStatCard(val iconType: Int, title: String, val heroColor: Color) : JPanel(BorderLayout()) {
    val valLabel = JLabel("0").apply {
        font = Font("Segoe UI", Font.BOLD, 15)
        foreground = heroColor
    }
    val subLabel = JLabel("Hazır").apply {
        font = Font("Segoe UI", Font.PLAIN, 10)
        foreground = Color(100, 116, 139)
    }

    init {
        background = Color(14, 22, 38)
        border = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color(30, 41, 59), 1),
            BorderFactory.createEmptyBorder(6, 10, 6, 10),
        )
        val header = JPanel(FlowLayout(FlowLayout.LEFT, 5, 0)).apply {
            isOpaque = false
            val iconPanel = object : JPanel() {
                init {
                    preferredSize = Dimension(16, 16)
                    isOpaque = false
                }
                override fun paintComponent(g: Graphics) {
                    super.paintComponent(g)
                    val g2 = g.create() as Graphics2D
                    g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
                    g2.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE)
                    when (iconType) {
                        0 -> SwingVectorIcons.drawBolt(g2, 8, 8, 16, heroColor)
                        1 -> SwingVectorIcons.drawLock(g2, 8, 8, 16, heroColor)
                        2 -> SwingVectorIcons.drawRadar(g2, 8, 8, 16, heroColor)
                        else -> SwingVectorIcons.drawGlobe(g2, 8, 8, 16, heroColor)
                    }
                    g2.dispose()
                }
            }
            val titleLabel = JLabel(title).apply {
                font = Font("Segoe UI", Font.BOLD, 10)
                foreground = Color(148, 163, 184)
            }
            add(iconPanel)
            add(titleLabel)
        }
        add(header, BorderLayout.NORTH)
        add(valLabel, BorderLayout.CENTER)
        add(subLabel, BorderLayout.SOUTH)
    }

    fun update(mainText: String, detailText: String) {
        valLabel.text = mainText
        subLabel.text = detailText
    }
}

typealias StatCard = ModernStatCard

/** Custom anti-aliased flat dark button immune to WindowsLookAndFeel / Metal white painting bugs. */
class FreedomButton(
    text: String,
    fillColor: Color = Color(30, 41, 59),
    textColor: Color = Color(226, 232, 240),
    var borderColor: Color = Color(51, 65, 85),
    private val arc: Int = 10,
    private val leftAlign: Boolean = false,
    private val iconDrawer: ((Graphics2D, Int, Int, Int, Color) -> Unit)? = null,
) : JButton(text) {
    private var hovered = false
    private var pressed = false

    init {
        setUI(BasicButtonUI())
        background = fillColor
        foreground = textColor
        font = Font("Segoe UI", Font.BOLD, 11)
        isContentAreaFilled = false
        isBorderPainted = false
        isFocusPainted = false
        isRolloverEnabled = false
        isFocusable = false
        isOpaque = false
        border = BorderFactory.createEmptyBorder()
        cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
        margin = Insets(6, 14, 6, 14)
        addMouseListener(object : MouseAdapter() {
            override fun mouseEntered(e: MouseEvent) {
                hovered = true
                repaint()
            }
            override fun mouseExited(e: MouseEvent) {
                hovered = false
                pressed = false
                repaint()
            }
            override fun mousePressed(e: MouseEvent) {
                pressed = true
                repaint()
            }
            override fun mouseReleased(e: MouseEvent) {
                pressed = false
                repaint()
            }
        })
    }

    override fun updateUI() {
        setUI(BasicButtonUI())
        isContentAreaFilled = false
        isBorderPainted = false
        isFocusPainted = false
        isRolloverEnabled = false
        isFocusable = false
        isOpaque = false
        border = BorderFactory.createEmptyBorder()
    }

    override fun paintBorder(g: Graphics) {
        // Rendered inside paintComponent with anti-aliasing; never let LAF paint white chrome.
    }

    override fun getPreferredSize(): Dimension {
        if (isPreferredSizeSet) return super.getPreferredSize()
        val label = text ?: ""
        val fm = getFontMetrics(font)
        if (label.isEmpty() && iconDrawer != null) {
            val w = maxOf(28, margin.left + margin.right + 14)
            val h = maxOf(28, fm.height + margin.top + margin.bottom)
            return Dimension(w, h)
        }
        val iconReserve = if (iconDrawer != null) 22 else 0
        val w = fm.stringWidth(label) + margin.left + margin.right + 4 + iconReserve
        val h = maxOf(32, fm.height + margin.top + margin.bottom)
        return Dimension(w, h)
    }

    private fun shiftColor(c: Color, delta: Int): Color = Color(
        (c.red + delta).coerceIn(0, 255),
        (c.green + delta).coerceIn(0, 255),
        (c.blue + delta).coerceIn(0, 255),
    )

    override fun paintComponent(g: Graphics) {
        val g2 = g.create() as Graphics2D
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON)
        g2.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE)

        val w = width
        val h = height
        val fill = when {
            !isEnabled -> Color(22, 31, 48)
            pressed -> shiftColor(background, -18)
            hovered -> shiftColor(background, 16)
            else -> background
        }
        val bCol = when {
            !isEnabled -> Color(36, 48, 68)
            hovered -> shiftColor(borderColor, 28)
            else -> borderColor
        }
        g2.color = fill
        g2.fillRoundRect(0, 0, w - 1, h - 1, arc, arc)
        g2.color = bCol
        g2.stroke = BasicStroke(1f)
        g2.drawRoundRect(0, 0, w - 1, h - 1, arc, arc)

        val label = text ?: ""
        val fgColor = if (isEnabled) foreground else Color(100, 116, 139)
        g2.font = font
        val fm = g2.fontMetrics
        val drawer = iconDrawer
        val ty = ((h - fm.height) / 2) + fm.ascent
        if (drawer != null) {
            if (label.isEmpty()) {
                val iconSz = minOf(20, minOf(w, h) - 6).coerceAtLeast(12)
                drawer(g2, w / 2, h / 2, iconSz, fgColor)
            } else if (leftAlign) {
                val iconCx = 19
                drawer(g2, iconCx, h / 2, 15, fgColor)
                g2.color = fgColor
                g2.drawString(label, 36, ty)
            } else {
                val totalW = 16 + 7 + fm.stringWidth(label)
                val startX = ((w - totalW) / 2).coerceAtLeast(8)
                drawer(g2, startX + 8, h / 2, 15, fgColor)
                g2.color = fgColor
                g2.drawString(label, startX + 23, ty)
            }
        } else if (label.isNotEmpty()) {
            g2.color = fgColor
            val tx = if (leftAlign) 14 else ((w - fm.stringWidth(label)) / 2).coerceAtLeast(6)
            g2.drawString(label, tx, ty)
        }
        g2.dispose()
    }
}

/** Slim dark scrollbar UI without bright native Win32/Metal chrome. */
private class DarkScrollBarUI : BasicScrollBarUI() {
    override fun configureScrollBarColors() {
        thumbColor = Color(51, 65, 85)
        thumbDarkShadowColor = Color(30, 41, 59)
        thumbHighlightColor = Color(71, 85, 105)
        trackColor = Color(9, 13, 22)
        trackHighlightColor = Color(9, 13, 22)
    }

    private fun zeroBtn(): JButton = JButton().apply {
        preferredSize = Dimension(0, 0)
        minimumSize = Dimension(0, 0)
        maximumSize = Dimension(0, 0)
        isVisible = false
    }

    override fun createDecreaseButton(orientation: Int): JButton = zeroBtn()
    override fun createIncreaseButton(orientation: Int): JButton = zeroBtn()

    override fun paintTrack(g: Graphics, c: JComponent, trackBounds: java.awt.Rectangle) {
        g.color = Color(9, 13, 22)
        g.fillRect(trackBounds.x, trackBounds.y, trackBounds.width, trackBounds.height)
    }

    override fun paintThumb(g: Graphics, c: JComponent, thumbBounds: java.awt.Rectangle) {
        if (thumbBounds.isEmpty || !scrollbar.isEnabled) return
        val g2 = g.create() as Graphics2D
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        g2.color = if (isThumbRollover || isDragging) Color(71, 85, 105) else Color(51, 65, 85)
        g2.fillRoundRect(thumbBounds.x + 2, thumbBounds.y + 2, thumbBounds.width - 4, thumbBounds.height - 4, 6, 6)
        g2.dispose()
    }
}

/** Crisp dark vector checkbox icon (never renders white native box). */
internal class DarkCheckBoxIcon(private val selected: Boolean) : Icon {
    override fun getIconWidth(): Int = 16
    override fun getIconHeight(): Int = 16

    override fun paintIcon(c: java.awt.Component?, g: Graphics, x: Int, y: Int) {
        val g2 = g.create() as Graphics2D
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        g2.color = if (selected) Color(14, 116, 144) else Color(14, 22, 38)
        g2.fillRoundRect(x + 1, y + 1, 14, 14, 5, 5)
        g2.color = if (selected) Color(56, 189, 248) else Color(71, 85, 105)
        g2.stroke = BasicStroke(1.3f)
        g2.drawRoundRect(x + 1, y + 1, 14, 14, 5, 5)
        if (selected) {
            g2.color = Color.WHITE
            g2.stroke = BasicStroke(2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
            g2.drawLine(x + 4, y + 8, x + 7, y + 11)
            g2.drawLine(x + 7, y + 11, x + 12, y + 5)
        }
        g2.dispose()
    }
}

/** Installs CrossPlatform dark LookAndFeel defaults so no Swing popup/tooltip/viewport/control renders white. */
internal object FreedomDarkTheme {
    @Volatile private var installed = false

    fun ensureInstalled() {
        if (!installed) install()
    }

    fun install() {
        runCatching { UIManager.setLookAndFeel(UIManager.getCrossPlatformLookAndFeelClassName()) }
        val bg = Color(7, 11, 20)
        val surface = Color(14, 22, 38)
        val fg = Color(226, 232, 240)
        val muted = Color(148, 163, 184)
        val disabledFg = Color(100, 116, 139)
        val border = Color(30, 41, 59)
        val accent = Color(56, 189, 248)
        val transparent = Color(0, 0, 0, 0)
        UIManager.put("control", bg)
        UIManager.put("window", bg)
        UIManager.put("windowText", fg)
        UIManager.put("desktop", bg)
        UIManager.put("info", surface)
        UIManager.put("infoText", fg)
        UIManager.put("text", fg)
        UIManager.put("Focus.color", transparent)
        UIManager.put("Panel.background", bg)
        UIManager.put("Panel.foreground", fg)
        UIManager.put("Label.background", bg)
        UIManager.put("Label.foreground", fg)
        UIManager.put("Button.background", Color(30, 41, 59))
        UIManager.put("Button.foreground", fg)
        UIManager.put("Button.select", Color(51, 65, 85))
        UIManager.put("Button.focus", transparent)
        UIManager.put("Button.disabledText", disabledFg)
        UIManager.put("Button.highlight", Color(51, 65, 85))
        UIManager.put("Button.light", border)
        UIManager.put("Button.shadow", border)
        UIManager.put("Button.darkShadow", bg)
        UIManager.put("Button.border", BorderFactory.createEmptyBorder())
        UIManager.put("ToggleButton.background", Color(30, 41, 59))
        UIManager.put("ToggleButton.foreground", fg)
        UIManager.put("ToggleButton.select", Color(51, 65, 85))
        UIManager.put("ToggleButton.focus", transparent)
        UIManager.put("ToggleButton.disabledText", disabledFg)
        UIManager.put("CheckBox.background", bg)
        UIManager.put("CheckBox.foreground", muted)
        UIManager.put("CheckBox.focus", transparent)
        UIManager.put("RadioButton.background", bg)
        UIManager.put("RadioButton.foreground", muted)
        UIManager.put("RadioButton.focus", transparent)
        UIManager.put("ComboBox.background", surface)
        UIManager.put("ComboBox.foreground", fg)
        UIManager.put("ComboBox.disabledBackground", surface)
        UIManager.put("ComboBox.disabledForeground", disabledFg)
        UIManager.put("ComboBox.selectionBackground", Color(30, 58, 138))
        UIManager.put("ComboBox.selectionForeground", Color.WHITE)
        UIManager.put("ComboBox.buttonBackground", Color(23, 34, 54))
        UIManager.put("ComboBox.buttonShadow", border)
        UIManager.put("ComboBox.buttonDarkShadow", bg)
        UIManager.put("ComboBox.buttonHighlight", Color(51, 65, 85))
        UIManager.put("ComboBox.border", BorderFactory.createLineBorder(Color(38, 52, 74), 1))
        UIManager.put("List.background", surface)
        UIManager.put("List.foreground", fg)
        UIManager.put("List.selectionBackground", Color(30, 58, 138))
        UIManager.put("List.selectionForeground", Color.WHITE)
        UIManager.put("PopupMenu.background", surface)
        UIManager.put("PopupMenu.foreground", fg)
        UIManager.put("PopupMenu.border", BorderFactory.createLineBorder(border, 1))
        UIManager.put("Menu.background", surface)
        UIManager.put("Menu.foreground", fg)
        UIManager.put("Menu.selectionBackground", Color(30, 58, 138))
        UIManager.put("Menu.selectionForeground", Color.WHITE)
        UIManager.put("MenuBar.background", bg)
        UIManager.put("MenuBar.foreground", fg)
        UIManager.put("MenuItem.background", surface)
        UIManager.put("MenuItem.foreground", fg)
        UIManager.put("MenuItem.selectionBackground", Color(30, 58, 138))
        UIManager.put("MenuItem.selectionForeground", Color.WHITE)
        UIManager.put("TextArea.background", surface)
        UIManager.put("TextArea.foreground", fg)
        UIManager.put("TextArea.inactiveBackground", surface)
        UIManager.put("TextArea.disabledBackground", surface)
        UIManager.put("TextArea.inactiveForeground", muted)
        UIManager.put("TextArea.caretForeground", accent)
        UIManager.put("TextArea.selectionBackground", Color(37, 99, 235))
        UIManager.put("TextArea.selectionForeground", Color.WHITE)
        UIManager.put("TextField.background", surface)
        UIManager.put("TextField.foreground", fg)
        UIManager.put("TextField.inactiveBackground", surface)
        UIManager.put("TextField.disabledBackground", surface)
        UIManager.put("TextField.inactiveForeground", muted)
        UIManager.put("TextField.caretForeground", accent)
        UIManager.put("TextField.selectionBackground", Color(37, 99, 235))
        UIManager.put("TextField.selectionForeground", Color.WHITE)
        UIManager.put("CheckBox.disabledText", disabledFg)
        UIManager.put("Label.disabledForeground", disabledFg)
        UIManager.put("ScrollPane.background", bg)
        UIManager.put("ScrollPane.border", BorderFactory.createLineBorder(border, 1))
        UIManager.put("Viewport.background", surface)
        UIManager.put("Viewport.foreground", fg)
        UIManager.put("ScrollBar.background", Color(9, 13, 22))
        UIManager.put("ScrollBar.track", Color(9, 13, 22))
        UIManager.put("ScrollBar.thumb", Color(51, 65, 85))
        UIManager.put("ScrollBar.thumbShadow", border)
        UIManager.put("ScrollBar.thumbHighlight", Color(71, 85, 105))
        UIManager.put("ScrollBar.shadow", Color(9, 13, 22))
        UIManager.put("ScrollBar.darkShadow", Color(9, 13, 22))
        UIManager.put("ScrollBar.highlight", border)
        UIManager.put("ScrollBar.width", 10)
        UIManager.put("ToolTip.background", surface)
        UIManager.put("ToolTip.foreground", fg)
        UIManager.put("ToolTip.border", BorderFactory.createLineBorder(border, 1))
        UIManager.put("OptionPane.background", bg)
        UIManager.put("OptionPane.messageForeground", fg)
        val lafDefaults = UIManager.getLookAndFeelDefaults()
        val userDefaults = UIManager.getDefaults()
        for (gradKey in listOf(
            "Button.gradient",
            "ToggleButton.gradient",
            "CheckBox.gradient",
            "RadioButton.gradient",
            "ComboBox.gradient",
            "ScrollBar.gradient",
            "Slider.gradient",
            "MenuBar.gradient",
            "MenuItem.gradient",
            "CheckBoxMenuItem.gradient",
            "RadioButtonMenuItem.gradient",
            "TabbedPane.gradient",
            "InternalFrame.activeTitleGradient",
        )) {
            userDefaults.remove(gradKey)
            lafDefaults.remove(gradKey)
        }
        installed = true
    }

    fun darkScrollPane(view: JComponent, showBorder: Boolean = true): JScrollPane = JScrollPane(view).apply {
        background = Color(9, 13, 22)
        viewport.background = if (showBorder) Color(9, 13, 22) else Color(7, 11, 20)
        border = if (showBorder) BorderFactory.createLineBorder(Color(30, 41, 59), 1) else BorderFactory.createEmptyBorder()
        verticalScrollBar.apply {
            setUI(DarkScrollBarUI())
            preferredSize = Dimension(10, 0)
            unitIncrement = 16
        }
        horizontalScrollBar.apply {
            setUI(DarkScrollBarUI())
            preferredSize = Dimension(0, 10)
            unitIncrement = 16
        }
        setCorner(ScrollPaneConstants.LOWER_RIGHT_CORNER, JPanel().apply { background = Color(9, 13, 22) })
    }

    fun styleField(tf: JTextField, tooltip: String = ""): JTextField = tf.apply {
        background = Color(14, 22, 38)
        foreground = Color(241, 245, 249)
        caretColor = Color(56, 189, 248)
        selectionColor = Color(37, 99, 235)
        selectedTextColor = Color.WHITE
        disabledTextColor = Color(100, 116, 139)
        font = Font("Segoe UI", Font.PLAIN, 12)
        border = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color(38, 52, 74), 1),
            BorderFactory.createEmptyBorder(5, 8, 5, 8),
        )
        if (tooltip.isNotEmpty()) toolTipText = tooltip
    }

    fun styleCombo(cb: JComboBox<String>): JComboBox<String> = cb.apply {
        background = Color(14, 22, 38)
        foreground = Color(226, 232, 240)
        font = Font("Segoe UI", Font.PLAIN, 12)
        border = BorderFactory.createLineBorder(Color(38, 52, 74), 1)
        isOpaque = true
        isFocusable = false
        setUI(object : BasicComboBoxUI() {
            override fun installDefaults() {
                super.installDefaults()
                comboBox.background = Color(14, 22, 38)
                comboBox.foreground = Color(226, 232, 240)
                comboBox.isOpaque = true
            }

            override fun createArrowButton(): JButton = FreedomButton(
                text = "",
                fillColor = Color(23, 34, 54),
                textColor = Color(226, 232, 240),
                borderColor = Color(51, 65, 85),
                arc = 6,
                iconDrawer = { g2, cx, cy, sz, col ->
                    SwingVectorIcons.drawIcon(g2, FreedomIconId.CHEVRON_DOWN, cx, cy, sz, col, 2.2f)
                },
            ).apply {
                preferredSize = Dimension(28, 28)
            }

            override fun createPopup(): ComboPopup = object : BasicComboPopup(comboBox) {
                override fun configurePopup() {
                    super.configurePopup()
                    background = Color(14, 22, 38)
                    border = BorderFactory.createLineBorder(Color(56, 189, 248), 1)
                }

                override fun configureList() {
                    super.configureList()
                    list.background = Color(14, 22, 38)
                    list.foreground = Color(226, 232, 240)
                    list.selectionBackground = Color(30, 58, 138)
                    list.selectionForeground = Color.WHITE
                }

                override fun configureScroller() {
                    super.configureScroller()
                    scroller.background = Color(9, 13, 22)
                    scroller.viewport.background = Color(14, 22, 38)
                    scroller.verticalScrollBar.apply {
                        setUI(DarkScrollBarUI())
                        preferredSize = Dimension(10, 0)
                    }
                }
            }

            override fun paintCurrentValueBackground(g: Graphics, bounds: java.awt.Rectangle, hasFocus: Boolean) {
                g.color = Color(14, 22, 38)
                g.fillRect(bounds.x, bounds.y, bounds.width, bounds.height)
            }
        })
        renderer = object : javax.swing.DefaultListCellRenderer() {
            override fun getListCellRendererComponent(
                list: javax.swing.JList<*>?,
                value: Any?,
                index: Int,
                isSelected: Boolean,
                cellHasFocus: Boolean,
            ): java.awt.Component {
                val lbl = super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus) as JLabel
                lbl.isOpaque = true
                lbl.background = if (isSelected) Color(30, 58, 138) else Color(14, 22, 38)
                lbl.foreground = if (isSelected) Color.WHITE else Color(226, 232, 240)
                lbl.border = BorderFactory.createEmptyBorder(4, 8, 4, 8)
                return lbl
            }
        }
    }
}

/**
 * Reversible Windows HKCU WinINet system proxy helper (`Internet Settings`).
 * Captures prior `ProxyEnable`/`ProxyServer`/`ProxyOverride` values once (discarding stale loopback
 * leftovers via `sanitizeCapturedProxy`) and restores them on stop or JVM shutdown.
 */
object WindowsSystemProxy {
    private const val REG_KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
    private val isWindows = System.getProperty("os.name").lowercase(Locale.US).contains("windows")

    @Volatile var appliedByApp = false
        private set
    private var prevCaptured = false
    private var prevEnable = 0
    private var prevServer: String? = null
    private var prevOverride: String? = null
    private val hookRegistered = AtomicBoolean(false)

    internal fun sanitizeCapturedProxy(enable: Int, server: String?): Pair<Int, String?> {
        val srv = server?.trim()?.takeIf { it.isNotEmpty() }
        if (enable != 1 || srv == null) return 0 to null
        val lower = srv.lowercase(Locale.US)
        if (lower.startsWith("127.0.0.1:") ||
            lower.startsWith("localhost:") ||
            lower.startsWith("[::1]:") ||
            lower == "127.0.0.1" ||
            lower == "localhost" ||
            lower.contains("=127.0.0.1:") ||
            lower.contains("=localhost:")
        ) {
            return 0 to null
        }
        return 1 to srv
    }

    private fun runCmd(vararg cmd: String): Pair<Int, String> {
        val pb = ProcessBuilder(*cmd).redirectErrorStream(true)
        val p = pb.start()
        val out = p.inputStream.bufferedReader().readText()
        val code = if (p.waitFor(4, TimeUnit.SECONDS)) p.exitValue() else { p.destroyForcibly(); -1 }
        return code to out
    }

    private fun queryRegValue(name: String): String? {
        if (!isWindows) return null
        val (rc, out) = runCmd("reg", "query", REG_KEY, "/v", name)
        if (rc != 0) return null
        val line = out.lines().firstOrNull { it.trim().startsWith(name, ignoreCase = true) } ?: return null
        return line.trim().split(Regex("\\s+"), limit = 3).getOrNull(2)?.trim()
    }

    private fun notifyWinInet(async: Boolean = false) {
        if (!isWindows) return
        val task = Runnable {
            runCatching {
                val ps = """
                    Add-Type -MemberDefinition '[DllImport("wininet.dll", SetLastError=true)] public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);' -Name WinInet -Namespace Freedom
                    [Freedom.WinInet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
                    [Freedom.WinInet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null
                """.trimIndent().replace("\n", "; ")
                runCmd("powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps)
            }
        }
        if (async) {
            Thread(task, "freedom-wininet-notify").apply {
                isDaemon = true
                start()
            }
        } else {
            task.run()
        }
    }

    @Synchronized
    fun enable(port: Int): Boolean {
        if (!isWindows || port !in 1..65535) return false
        if (hookRegistered.compareAndSet(false, true)) {
            runCatching { Runtime.getRuntime().addShutdownHook(Thread { restore(asyncWinInet = true) }) }
        }
        if (!prevCaptured) {
            val rawEnable = queryRegValue("ProxyEnable")?.let { raw ->
                if (raw.startsWith("0x", ignoreCase = true)) raw.substring(2).toIntOrNull(16) else raw.toIntOrNull()
            } ?: 0
            val rawServer = queryRegValue("ProxyServer")
            val (sanEn, sanSrv) = sanitizeCapturedProxy(rawEnable, rawServer)
            prevEnable = sanEn
            prevServer = sanSrv
            prevOverride = if (sanEn == 0) null else queryRegValue("ProxyOverride")
            prevCaptured = true
        }
        val (r1, _) = runCmd("reg", "add", REG_KEY, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f")
        val (r2, _) = runCmd("reg", "add", REG_KEY, "/v", "ProxyServer", "/t", "REG_SZ", "/d", "127.0.0.1:$port", "/f")
        val (r3, _) = runCmd("reg", "add", REG_KEY, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", "localhost;127.*;10.*;192.168.*;<local>", "/f")
        if (r1 == 0 && r2 == 0 && r3 == 0) {
            appliedByApp = true
            notifyWinInet(async = false)
            return true
        }
        return false
    }

    @Synchronized
    fun restore(asyncWinInet: Boolean = false) {
        if (!isWindows || !appliedByApp) return
        runCmd("reg", "add", REG_KEY, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", prevEnable.toString(), "/f")
        val oldSrv = prevServer
        if (!oldSrv.isNullOrBlank()) {
            runCmd("reg", "add", REG_KEY, "/v", "ProxyServer", "/t", "REG_SZ", "/d", oldSrv, "/f")
        } else {
            runCmd("reg", "delete", REG_KEY, "/v", "ProxyServer", "/f")
        }
        val oldOvr = prevOverride
        if (!oldOvr.isNullOrBlank()) {
            runCmd("reg", "add", REG_KEY, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", oldOvr, "/f")
        } else {
            runCmd("reg", "delete", REG_KEY, "/v", "ProxyOverride", "/f")
        }
        appliedByApp = false
        notifyWinInet(async = asyncWinInet)
    }
}

/** Dark glass rounded card container with crisp border and zero native Swing chrome. */
private class GlassCardPanel(
    private val cardBg: Color = Color(12, 19, 34),
    private var cardBorder: Color = Color(30, 41, 59),
    private val arc: Int = 14,
) : JPanel(BorderLayout(8, 6)) {
    init {
        isOpaque = false
        border = BorderFactory.createEmptyBorder(11, 13, 11, 13)
    }

    override fun paintComponent(g: Graphics) {
        val g2 = g.create() as Graphics2D
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        g2.color = cardBg
        g2.fillRoundRect(0, 0, width - 1, height - 1, arc, arc)
        g2.color = cardBorder
        g2.stroke = BasicStroke(1f)
        g2.drawRoundRect(0, 0, width - 1, height - 1, arc, arc)
        g2.dispose()
        super.paintComponent(g)
    }
}

private object FreedomUiHelpers {
    fun pillLabel(text: String, fg: Color = Color(148, 163, 184), bg: Color = Color(13, 21, 37), borderCol: Color = Color(30, 41, 59)): JLabel =
        JLabel(text, SwingConstants.CENTER).apply {
            isOpaque = true
            background = bg
            foreground = fg
            font = Font("Segoe UI", Font.BOLD, 10)
            border = BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(borderCol, 1),
                BorderFactory.createEmptyBorder(4, 10, 4, 10),
            )
        }

    fun sectionHeader(title: String, accent: Color, rightComp: java.awt.Component? = null): JPanel =
        JPanel(BorderLayout(8, 0)).apply {
            isOpaque = false
            add(
                JLabel(title).apply {
                    font = Font("Segoe UI", Font.BOLD, 10)
                    foreground = accent
                },
                BorderLayout.WEST,
            )
            if (rightComp != null) add(rightComp, BorderLayout.EAST)
        }

    fun darkCheckBox(text: String, checked: Boolean): JCheckBox = JCheckBox(text, checked).apply {
        foreground = Color(203, 213, 225)
        background = Color(12, 19, 34)
        isOpaque = false
        isContentAreaFilled = false
        isBorderPainted = false
        isFocusPainted = false
        isRolloverEnabled = false
        isFocusable = false
        icon = DarkCheckBoxIcon(false)
        selectedIcon = DarkCheckBoxIcon(true)
        rolloverIcon = DarkCheckBoxIcon(false)
        rolloverSelectedIcon = DarkCheckBoxIcon(true)
        pressedIcon = DarkCheckBoxIcon(true)
        disabledIcon = DarkCheckBoxIcon(false)
        disabledSelectedIcon = DarkCheckBoxIcon(true)
        iconTextGap = 8
        font = Font("Segoe UI", Font.PLAIN, 11)
        cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
    }

    fun monoLogArea(initial: String, fgColor: Color): JTextArea = JTextArea().apply {
        isEditable = false
        font = Font(Font.MONOSPACED, Font.PLAIN, 12)
        lineWrap = true
        wrapStyleWord = true
        background = Color(8, 13, 24)
        foreground = fgColor
        selectionColor = Color(37, 99, 235)
        selectedTextColor = Color.WHITE
        caretColor = Color(56, 189, 248)
        border = BorderFactory.createEmptyBorder(8, 10, 8, 10)
        text = initial
    }

    fun clipboardCopy(text: String, statusLabel: JLabel, msg: String) {
        runCatching {
            val sel = StringSelection(text)
            Toolkit.getDefaultToolkit().systemClipboard.setContents(sel, sel)
        }
        statusLabel.text = msg
    }
}

/**
 * MainWindow:
 * Freedom Network 2026–2027 4-Workspace Obsidian/Glass Command Center for Windows 10/11:
 * 0. Kontrol Merkezi (Hero Shield, Auto-WARP/DPI/Relay Routing, Live IP Verification, Sparkline & 2x2 Cards)
 * 1. Tarayıcı & Gizlilik (Isolated QUIC-free Chromium Launcher, DevicePersona Masking, Leak Shield & Dual-Path Test)
 * 2. Ağ Teşhis Lab (Preset Censorship Targets, DoH/Alt-DNS Diagnostics, Verification & Copy)
 * 3. Sistem & Günlük (Real-time Internal Engine Log Bus & System-Wide Socket Snapshot Inspector)
 */
class MainWindow {
    companion object {
        init {
            FreedomDarkTheme.ensureInstalled()
        }
    }

    private val frame: JFrame by lazy { JFrame("Freedom Network — 2026–2027 Özgür Ağ Komuta Merkezi") }
    private val pulsePanel = ModernPowerShieldPanel().apply { preferredSize = Dimension(320, 176) }
    private val sparkline = ThroughputSparklinePanel().apply { preferredSize = Dimension(380, 108) }
    private val cardTcp = ModernStatCard(0, "TÜNEL & DPI", Color(16, 185, 129))
    private val cardVision = ModernStatCard(1, "İZLEYİCİ & URL", Color(56, 189, 248))
    private val cardFake = ModernStatCard(2, "QUIC & STUN KALKANI", Color(167, 139, 250))
    private val cardDns = ModernStatCard(3, "ŞİFRELİ DoH3 / ECH", Color(251, 191, 36))

    private val proxyLock = ReentrantLock()
    @Volatile private var activeProxy: WindowsNextGenProxy? = null
    @Volatile private var selectedRouteMode = WindowsRouteMode.AUTO_WARP
    @Volatile private var selectedPersona = DevicePersona.IPHONE_19_BETA
    @Volatile private var systemProxyDesired = true
    @Volatile private var blockTrackersDesired = true
    @Volatile private var stripUrlParamsDesired = true
    @Volatile private var blockQuicLeaksDesired = true

    private var activeWorkspaceIdx = 0
    private var builtRoot: JPanel? = null

    private val topRoutePill = FreedomUiHelpers.pillLabel("Rota: Hazır · WARP / DoH3", Color(56, 189, 248))
    private val topDnsQuicPill = FreedomUiHelpers.pillLabel("DoH3 + QUIC Kalkanı: Açık", Color(16, 185, 129))
    private val topPersonaPill = FreedomUiHelpers.pillLabel("Kimlik: iPhone 19 Beta", Color(196, 181, 253))
    private val topSysProxyPill = FreedomUiHelpers.pillLabel("Sistem Vekili: Otomatik", Color(251, 191, 36))
    private val sidebarStateBadge = FreedomUiHelpers.pillLabel("HAZIR", Color(148, 163, 184), Color(15, 23, 42), Color(51, 65, 85)).apply {
        icon = SwingVectorIcons.asSwingIcon(FreedomIconId.SHIELD_OFF, 12, Color(148, 163, 184))
        iconTextGap = 6
    }

    private val navButtons = listOf(
        FreedomButton("Kontrol Merkezi", arc = 10, leftAlign = true, iconDrawer = SwingVectorIcons::drawShield),
        FreedomButton("Tarayıcı & Gizlilik", arc = 10, leftAlign = true, iconDrawer = SwingVectorIcons::drawGlobe),
        FreedomButton("Ağ Teşhis Lab", arc = 10, leftAlign = true, iconDrawer = SwingVectorIcons::drawRadar),
        FreedomButton("Sistem & Günlük", arc = 10, leftAlign = true, iconDrawer = SwingVectorIcons::drawTerminal),
    )
    private val btnQuickDiscord = FreedomButton(
        "Discord'u Korumalı Aç",
        fillColor = Color(30, 58, 138),
        textColor = Color.WHITE,
        borderColor = Color(56, 189, 248),
        arc = 10,
        iconDrawer = SwingVectorIcons::drawBolt,
    )

    private val statusPill = FreedomUiHelpers.pillLabel(
        "KORUMA KAPALI · TEK TIKLA BAĞLANIN",
        fg = Color(148, 163, 184),
        bg = Color(10, 17, 30),
        borderCol = Color(30, 41, 59),
    )
    private val heroActionButton = FreedomButton(
        "ÖZGÜR AĞI BAŞLAT",
        fillColor = Color(16, 185, 129),
        textColor = Color(4, 22, 16),
        borderColor = Color(52, 211, 153),
        arc = 12,
        iconDrawer = SwingVectorIcons::drawPower,
    ).apply {
        font = Font("Segoe UI", Font.BOLD, 12)
        preferredSize = Dimension(310, 42)
    }

    private val btnModeWarp = FreedomButton("Otomatik WARP", arc = 8)
    private val btnModeHybrid = FreedomButton("Hızlı DPI", arc = 8)
    private val btnModeRelay = FreedomButton("Özel Röle", arc = 8)
    private val txtRelayUri = FreedomDarkTheme.styleField(
        JTextField("socks5://127.0.0.1:9050"),
        "Örnek: socks5://127.0.0.1:9050 veya http://user:pass@host:port",
    )
    private val btnSystemProxyToggle = FreedomButton(
        "WinINet Sistem Vekili: Otomatik Açık",
        fillColor = Color(15, 27, 46),
        textColor = Color(251, 191, 36),
        borderColor = Color(217, 119, 6),
        arc = 9,
        iconDrawer = { g2, cx, cy, sz, col ->
            SwingVectorIcons.drawIcon(g2, FreedomIconId.SLIDERS, cx, cy, sz, col, 1.9f)
        },
    )

    private val ipCardDetail = JLabel("Hazır · WARP WireGuard -> Tor :9050 -> Hibrit DPI + DoH3").apply {
        font = Font("Segoe UI", Font.BOLD, 11)
        foreground = Color(226, 232, 240)
    }
    private val directIpLabel = JLabel("Doğrudan Ağ IP: ölçülmedi").apply {
        font = Font("Segoe UI", Font.PLAIN, 10)
        foreground = Color(148, 163, 184)
    }
    private val proxyIpLabel = JLabel("Tünel / Vekil Çıkışı: koruma açıldığında doğrulanır").apply {
        font = Font("Segoe UI", Font.PLAIN, 10)
        foreground = Color(148, 163, 184)
    }
    private val btnVerifyIp = FreedomButton(
        "Canlı IP Doğrula",
        fillColor = Color(15, 27, 46),
        textColor = Color(56, 189, 248),
        borderColor = Color(29, 78, 216),
        arc = 9,
        iconDrawer = SwingVectorIcons::drawRadar,
    )

    private val detectedBrowsers = WindowsBrowserLauncher.detectBrowsers()
    private val cmbBrowser = FreedomDarkTheme.styleCombo(
        JComboBox<String>(
            if (detectedBrowsers.isNotEmpty()) {
                detectedBrowsers.map { it.name }.toTypedArray()
            } else {
                arrayOf("Chrome / Edge / Brave bulunamadı (Sistem Vekili Kullan)")
            },
        ),
    )
    private val txtBrowserUrl = FreedomDarkTheme.styleField(
        JTextField("https://discord.com/"),
        "Korumalı profilde açılacak hedef adres",
    )
    private val btnLaunchBrowser = FreedomButton(
        "Korumalı Tarayıcı Aç",
        fillColor = Color(16, 185, 129),
        textColor = Color(4, 22, 16),
        borderColor = Color(52, 211, 153),
        arc = 10,
        iconDrawer = SwingVectorIcons::drawGlobe,
    )
    private val btnLaunchDiscord = FreedomButton(
        "Discord'u Aç",
        fillColor = Color(30, 58, 138),
        textColor = Color.WHITE,
        borderColor = Color(56, 189, 248),
        arc = 10,
        iconDrawer = SwingVectorIcons::drawBolt,
    )
    private val browserLaunchStatus = JLabel("Hazır · İzole tarayıcı profili QUIC/WebRTC sızıntısını ve tarayıcı DNS kaçağını kapatır").apply {
        font = Font("Segoe UI", Font.PLAIN, 10)
        foreground = Color(148, 163, 184)
    }

    private val personaButtons = DevicePersona.entries.map { p ->
        p to FreedomButton(p.shortLabel, arc = 8)
    }
    private val chkBlockTrackers = FreedomUiHelpers.darkCheckBox("İzleyici, reklam & telemetri alan adlarını engelle (403 / SOCKS5 blok)", true)
    private val chkStripUrlParams = FreedomUiHelpers.darkCheckBox("URL takip parametrelerini temizle (utm_*, fbclid, gclid, si)", true)
    private val chkBlockQuicLeaks = FreedomUiHelpers.darkCheckBox("Null Island konum kalkanı + WebRTC UDP / QUIC / STUN engelle", true)
    private val btnLeakTest = FreedomButton(
        "Çift-Yol IP & Gizlilik Testini Çalıştır",
        fillColor = Color(15, 27, 46),
        textColor = Color(56, 189, 248),
        borderColor = Color(29, 78, 216),
        arc = 9,
        iconDrawer = { g2, cx, cy, sz, col ->
            SwingVectorIcons.drawShield(g2, cx, cy, sz, col, fill = false)
        },
    )
    private val leakTestResult = JLabel("Doğrudan çıkış vs Vekil/WARP çıkış karşılaştırması + Curve25519 Kripto denetimi hazır").apply {
        font = Font("Segoe UI", Font.PLAIN, 10)
        foreground = Color(148, 163, 184)
    }

    private val targets = JTextArea("cloudflare.com\nwikipedia.org\nietf.org", 3, 35).apply {
        background = Color(14, 22, 38)
        foreground = Color.WHITE
        selectionColor = Color(37, 99, 235)
        selectedTextColor = Color.WHITE
        caretColor = Color(56, 189, 248)
        font = Font("Segoe UI", Font.PLAIN, 12)
        border = BorderFactory.createEmptyBorder(5, 7, 5, 7)
    }
    private val altDns = FreedomDarkTheme.styleField(JTextField(24), "Karşılaştırılacak ek DNS sunucu IP (isteğe bağlı)")
    private val dohEndpoints = FreedomDarkTheme.styleField(JTextField(24), "Örnek: https://1.1.1.1/dns-query")
    private val runButton = FreedomButton(
        "Ağ Tanıla",
        fillColor = Color(37, 99, 235),
        textColor = Color.WHITE,
        borderColor = Color(59, 130, 246),
        iconDrawer = SwingVectorIcons::drawRadar,
    ).apply { font = Font("Segoe UI", Font.BOLD, 12) }
    private val appliedButton = FreedomButton(
        "Öneriyi Doğrula",
        fillColor = Color(30, 41, 59),
        textColor = Color(226, 232, 240),
        borderColor = Color(51, 65, 85),
        iconDrawer = SwingVectorIcons::drawCheck,
    ).apply { isEnabled = false }
    private val auto = FreedomUiHelpers.darkCheckBox("Ağ değişince yeniden tanıla", false)
    private val output = FreedomUiHelpers.monoLogArea(
        "Ağ Teşhis Laboratuvarı hazır. 'Ağ Tanıla' ile sansür, DNS zehirlenmesi ve QUIC uyumsuzluğunu ölçün.",
        Color(226, 232, 240),
    )

    private val telemetryBusy = AtomicBoolean(false)
    private val btnRefreshTelemetry = FreedomButton(
        "Canlı Ölç",
        fillColor = Color(30, 41, 59),
        textColor = Color(56, 189, 248),
        borderColor = Color(56, 189, 248),
        arc = 8,
        iconDrawer = { g2, cx, cy, sz, col ->
            SwingVectorIcons.drawIcon(g2, FreedomIconId.REFRESH_CW, cx, cy, sz, col, 2.0f)
        },
    )
    private val telemetryOutput = FreedomUiHelpers.monoLogArea(
        "Küresel gönüllü ağı (RIPE Atlas · OONI · M-Lab · Cloudflare) hazır. 'Canlı Ölç' ile sorgulayın.",
        Color(167, 243, 208),
    )

    private val systemButton = FreedomButton(
        "Sistem Bağlantılarını Tara",
        fillColor = Color(30, 41, 59),
        textColor = Color(226, 232, 240),
        borderColor = Color(71, 85, 105),
        iconDrawer = SwingVectorIcons::drawPulse,
    )
    private val motorLogOutput = FreedomUiHelpers.monoLogArea(
        "İç motor günlüğü başlatıldı (WARP / DoH3 / Adaptif TLS Bölme / Tarayıcı olayları burada canlı akar)...",
        Color(147, 197, 253),
    )
    private val logOutput = FreedomUiHelpers.monoLogArea(
        "Sistem geneli soket gözlemcisi hazır. Açık bağlantıları listelemek için 'Sistem Bağlantılarını Tara' düğmesine basın.",
        Color(167, 243, 208),
    )
    private val status = JLabel(" ").apply {
        foreground = Color(56, 189, 248)
        font = Font("Segoe UI", Font.PLAIN, 11)
    }

    private val cardLayout = CardLayout()
    private val centerContainer = JPanel(cardLayout).apply { background = Color(7, 11, 20) }

    private val worker: ExecutorService = Executors.newCachedThreadPool { r ->
        Thread(r, "freedom-ui-worker").apply { isDaemon = true }
    }
    private val busy = AtomicBoolean(false)
    private var session: DiagnosticSession? = null
    @Volatile private var lastEnv: EnvironmentInfo? = null
    @Volatile private var lastDecision: Decision? = null
    private val watcher = Timer(15_000) { worker.execute { checkNetwork() } }

    private var lastBytesDown = 0L
    private var lastBytesUp = 0L
    private var lastTickMs = 0L
    private var lastLogVersion = -1L

    private val ticker = Timer(1000) {
        val p = activeProxy
        if (p != null && p.isActive) {
            val ps = p.statusSnapshot()
            pulsePanel.isActive = true
            pulsePanel.portInfo = "127.0.0.1:${p.localPort}"

            cardTcp.update(
                "${ps.connections} Akış",
                "TLS Bölme: ${ps.tlsSplit} · 4x Uyum: ${p.tlsAdaptiveRetries.get()} · WARP: ${p.warpFlows.get()}",
            )
            cardVision.update(
                "${ps.trackersBlocked + ps.paramsStripped} Temiz",
                "İzleyici: ${ps.trackersBlocked} · URL: ${ps.paramsStripped}",
            )
            cardFake.update(
                "${p.leaksBlocked.get()} Engel",
                "QUIC/STUN Kalkanı · RST: ${ps.rstDropped}",
            )
            cardDns.update(
                "${p.dohResolved.get()} DoH",
                "Zehirli DNS: ${p.poisonedDnsBlocked.get()} · ${p.persona.shortLabel}",
            )

            val now = System.currentTimeMillis()
            val curDown = p.bytesDown.get()
            val curUp = p.bytesUp.get()
            val dtSec = if (lastTickMs > 0L) ((now - lastTickMs).coerceAtLeast(250L) / 1000f) else 1f
            val rxRate = if (lastTickMs > 0L) ((curDown - lastBytesDown).coerceAtLeast(0L) / 1024f) / dtSec else 0f
            val txRate = if (lastTickMs > 0L) ((curUp - lastBytesUp).coerceAtLeast(0L) / 1024f) / dtSec else 0f
            lastBytesDown = curDown
            lastBytesUp = curUp
            lastTickMs = now
            sparkline.updateMetrics(rxRate, txRate, curDown, curUp)
            updateProtectionVisuals(ps, p.routeLabel, p.isIpMasked)
        } else {
            pulsePanel.isActive = false
            pulsePanel.portInfo = ""
            lastTickMs = System.currentTimeMillis()
            lastBytesDown = 0L
            lastBytesUp = 0L
            sparkline.updateMetrics(0f, 0f, 0L, 0L)
            updateProtectionVisuals(null, selectedRouteMode.subtitleTr, false)
        }

        val (logVer, logText) = WindowsLogBus.snapshot()
        if (logVer != lastLogVersion) {
            lastLogVersion = logVer
            motorLogOutput.text = logText.ifBlank { "Henüz motor olay kaydı yok." }
            motorLogOutput.caretPosition = motorLogOutput.document.length
        }
    }

    private fun buildNavRail(): JPanel {
        val rail = JPanel(BorderLayout(0, 12)).apply {
            preferredSize = Dimension(224, 0)
            background = Color(9, 14, 26)
            border = BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 0, 1, Color(26, 37, 56)),
                BorderFactory.createEmptyBorder(16, 14, 16, 14),
            )
        }

        val topBrand = JPanel(BorderLayout(10, 8)).apply {
            isOpaque = false
            val emblem = object : JPanel() {
                init {
                    preferredSize = Dimension(38, 38)
                    isOpaque = false
                }
                override fun paintComponent(g: Graphics) {
                    super.paintComponent(g)
                    val g2 = g.create() as Graphics2D
                    g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
                    val active = activeProxy?.isActive == true
                    SwingVectorIcons.drawFreedomShieldEmblem(
                        g2,
                        19,
                        19,
                        32,
                        if (active) Color(16, 185, 129) else Color(56, 189, 248),
                        if (active) Color(34, 211, 238) else Color(129, 140, 248),
                    )
                    g2.dispose()
                }
            }
            val titleStack = JPanel(GridLayout(2, 1, 0, 1)).apply {
                isOpaque = false
                add(
                    JLabel("FREEDOM").apply {
                        font = Font("Segoe UI", Font.BOLD, 16)
                        foreground = Color(248, 250, 252)
                    },
                )
                add(
                    JLabel("2026–2027 · v2.5").apply {
                        font = Font("Segoe UI", Font.BOLD, 10)
                        foreground = Color(56, 189, 248)
                    },
                )
            }
            val brandHeader = JPanel(BorderLayout(8, 0)).apply {
                isOpaque = false
                add(emblem, BorderLayout.WEST)
                add(titleStack, BorderLayout.CENTER)
            }
            add(brandHeader, BorderLayout.NORTH)
            add(sidebarStateBadge, BorderLayout.SOUTH)
        }

        val navStack = JPanel(GridLayout(4, 1, 0, 8)).apply {
            isOpaque = false
            navButtons.forEachIndexed { idx, btn ->
                btn.preferredSize = Dimension(196, 40)
                btn.addActionListener { selectWorkspace(idx) }
                add(btn)
            }
        }
        val navHost = JPanel(BorderLayout()).apply {
            isOpaque = false
            border = BorderFactory.createEmptyBorder(14, 0, 0, 0)
            add(navStack, BorderLayout.NORTH)
        }

        val bottomBox = JPanel(BorderLayout(0, 6)).apply {
            isOpaque = false
            add(
                JLabel("Hızlı Sızıntısız Başlatma").apply {
                    font = Font("Segoe UI", Font.BOLD, 10)
                    foreground = Color(100, 116, 139)
                },
                BorderLayout.NORTH,
            )
            btnQuickDiscord.preferredSize = Dimension(196, 38)
            add(btnQuickDiscord, BorderLayout.CENTER)
        }

        rail.add(topBrand, BorderLayout.NORTH)
        rail.add(navHost, BorderLayout.CENTER)
        rail.add(bottomBox, BorderLayout.SOUTH)
        return rail
    }

    private fun buildTelemetryStrip(): JPanel {
        val bar = JPanel(BorderLayout()).apply {
            background = Color(8, 12, 22)
            border = BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, Color(26, 37, 56)),
                BorderFactory.createEmptyBorder(10, 16, 10, 16),
            )
        }
        val pills = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
            isOpaque = false
            add(topRoutePill)
            add(topDnsQuicPill)
            add(topPersonaPill)
            add(topSysProxyPill)
        }
        bar.add(pills, BorderLayout.CENTER)
        return bar
    }

    private fun buildControlWorkspace(): JPanel {
        val panel = JPanel(GridBagLayout()).apply {
            background = Color(7, 11, 20)
            border = BorderFactory.createEmptyBorder(14, 16, 10, 16)
        }

        // Left Column: Hero Shield + Mode Routing + WinINet Proxy Toggle
        val leftCol = JPanel(GridBagLayout()).apply { isOpaque = false }
        val heroCard = GlassCardPanel().apply {
            val shieldHost = JPanel(BorderLayout()).apply {
                isOpaque = false
                add(pulsePanel, BorderLayout.CENTER)
            }
            val bottomStack = JPanel(GridLayout(2, 1, 0, 8)).apply {
                isOpaque = false
                add(statusPill)
                add(heroActionButton)
            }
            add(FreedomUiHelpers.sectionHeader("GÜVENLİK MOTORU VE TÜNEL DURUMU", Color(56, 189, 248)), BorderLayout.NORTH)
            add(shieldHost, BorderLayout.CENTER)
            add(bottomStack, BorderLayout.SOUTH)
        }

        val routingCard = GlassCardPanel().apply {
            val modeRow = JPanel(GridLayout(1, 3, 6, 0)).apply {
                isOpaque = false
                add(btnModeWarp)
                add(btnModeHybrid)
                add(btnModeRelay)
            }
            val relayRow = JPanel(BorderLayout(8, 0)).apply {
                isOpaque = false
                add(
                    JLabel("Röle URI:").apply {
                        font = Font("Segoe UI", Font.BOLD, 10)
                        foreground = Color(148, 163, 184)
                    },
                    BorderLayout.WEST,
                )
                add(txtRelayUri, BorderLayout.CENTER)
            }
            val midStack = JPanel(GridLayout(3, 1, 0, 8)).apply {
                isOpaque = false
                add(modeRow)
                add(relayRow)
                add(btnSystemProxyToggle)
            }
            add(FreedomUiHelpers.sectionHeader("ÇIKIŞ ROTASI & SİSTEM VEKİLİ (Yönetici İzni Gerektirmez)", Color(16, 185, 129)), BorderLayout.NORTH)
            add(midStack, BorderLayout.CENTER)
        }

        val lc = GridBagConstraints().apply {
            gridx = 0
            weightx = 1.0
            fill = GridBagConstraints.BOTH
        }
        lc.gridy = 0; lc.weighty = 0.57; lc.insets = Insets(0, 0, 10, 0); leftCol.add(heroCard, lc)
        lc.gridy = 1; lc.weighty = 0.43; lc.insets = Insets(0, 0, 0, 0); leftCol.add(routingCard, lc)

        // Right Column: Live Exit Route & IP Card + Sparkline + 2x2 Stats Grid
        val rightCol = JPanel(GridBagLayout()).apply { isOpaque = false }
        val routeIpCard = GlassCardPanel().apply {
            val infoStack = JPanel(GridLayout(3, 1, 0, 3)).apply {
                isOpaque = false
                add(ipCardDetail)
                add(directIpLabel)
                add(proxyIpLabel)
            }
            val actionWrap = JPanel(GridBagLayout()).apply {
                isOpaque = false
                add(btnVerifyIp)
            }
            add(FreedomUiHelpers.sectionHeader("ÇIKIŞ ROTASI & CANLI IP DOĞRULAMA", Color(56, 189, 248)), BorderLayout.NORTH)
            add(infoStack, BorderLayout.CENTER)
            add(actionWrap, BorderLayout.EAST)
        }
        val sparkCard = GlassCardPanel(cardBg = Color(10, 16, 29)).apply {
            border = BorderFactory.createEmptyBorder(8, 10, 8, 10)
            add(sparkline, BorderLayout.CENTER)
        }
        val grid2x2 = JPanel(GridLayout(2, 2, 8, 8)).apply {
            isOpaque = false
            add(cardTcp)
            add(cardVision)
            add(cardFake)
            add(cardDns)
        }

        val rc = GridBagConstraints().apply {
            gridx = 0
            weightx = 1.0
            fill = GridBagConstraints.BOTH
        }
        rc.gridy = 0; rc.weighty = 0.0; rc.insets = Insets(0, 0, 10, 0); rightCol.add(routeIpCard, rc)
        rc.gridy = 1; rc.weighty = 0.38; rc.insets = Insets(0, 0, 10, 0); rightCol.add(sparkCard, rc)
        rc.gridy = 2; rc.weighty = 0.62; rc.insets = Insets(0, 0, 0, 0); rightCol.add(grid2x2, rc)

        val mainC = GridBagConstraints().apply {
            gridy = 0
            weighty = 1.0
            fill = GridBagConstraints.BOTH
        }
        mainC.gridx = 0; mainC.weightx = 0.45; mainC.insets = Insets(0, 0, 0, 12); panel.add(leftCol, mainC)
        mainC.gridx = 1; mainC.weightx = 0.55; mainC.insets = Insets(0, 0, 0, 0); panel.add(rightCol, mainC)
        return panel
    }

    private fun buildPrivacyWorkspace(): JPanel {
        val stack = JPanel(GridBagLayout()).apply {
            background = Color(7, 11, 20)
            border = BorderFactory.createEmptyBorder(14, 16, 10, 16)
        }

        // Card 1: Protected Browser Launcher
        val browserCard = GlassCardPanel().apply {
            val form = JPanel(GridBagLayout()).apply { isOpaque = false }
            val fc = GridBagConstraints().apply { insets = Insets(3, 4, 3, 4); fill = GridBagConstraints.HORIZONTAL }
            fc.gridx = 0; fc.gridy = 0; fc.weightx = 0.0
            form.add(JLabel("Tarayıcı:").apply { foreground = Color(148, 163, 184); font = Font("Segoe UI", Font.PLAIN, 11) }, fc)
            fc.gridx = 1; fc.weightx = 0.45; form.add(cmbBrowser, fc)
            fc.gridx = 2; fc.weightx = 0.0
            form.add(JLabel("Hedef URL:").apply { foreground = Color(148, 163, 184); font = Font("Segoe UI", Font.PLAIN, 11) }, fc)
            fc.gridx = 3; fc.weightx = 0.55; form.add(txtBrowserUrl, fc)

            val quickUrlRow = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2)).apply {
                isOpaque = false
                add(
                    FreedomButton("Discord", arc = 7).apply {
                        addActionListener { txtBrowserUrl.text = "https://discord.com/" }
                    },
                )
                add(
                    FreedomButton("DuckDuckGo", arc = 7).apply {
                        addActionListener { txtBrowserUrl.text = "https://duckduckgo.com/" }
                    },
                )
                add(
                    FreedomButton("IP Kontrol", arc = 7).apply {
                        addActionListener { txtBrowserUrl.text = "https://api.ipify.org/" }
                    },
                )
                add(btnLaunchBrowser)
                add(btnLaunchDiscord)
            }
            val descLbl = JLabel("Chrome QUIC (UDP:443), WebRTC yerel IP sızıntısı, tarayıcı Async-DNS ve konum sensörü otomatik kapatılır.").apply {
                font = Font("Segoe UI", Font.PLAIN, 10)
                foreground = Color(100, 116, 139)
            }
            val body = JPanel(BorderLayout(0, 6)).apply {
                isOpaque = false
                add(form, BorderLayout.NORTH)
                add(quickUrlRow, BorderLayout.CENTER)
                add(descLbl, BorderLayout.SOUTH)
            }
            add(FreedomUiHelpers.sectionHeader("KORUMALI TARAYICI BAŞLATICISI (QUIC & WebRTC Sızıntısız)", Color(16, 185, 129)), BorderLayout.NORTH)
            add(body, BorderLayout.CENTER)
            add(browserLaunchStatus, BorderLayout.SOUTH)
        }

        // Card 2: DevicePersona & Leak Shields
        val personaCard = GlassCardPanel().apply {
            val btnRow = JPanel(GridLayout(1, personaButtons.size, 8, 0)).apply {
                isOpaque = false
                personaButtons.forEach { (p, b) ->
                    b.addActionListener { selectPersona(p) }
                    add(b)
                }
            }
            val chkStack = JPanel(GridLayout(3, 1, 0, 4)).apply {
                isOpaque = false
                add(chkBlockTrackers)
                add(chkStripUrlParams)
                add(chkBlockQuicLeaks)
            }
            val center = JPanel(BorderLayout(0, 10)).apply {
                isOpaque = false
                add(btnRow, BorderLayout.NORTH)
                add(chkStack, BorderLayout.CENTER)
            }
            add(FreedomUiHelpers.sectionHeader("CİHAZ KİMLİĞİ (HTTP / User-Agent Maskeleme) & SIZINTI KALKANLARI", Color(167, 139, 250)), BorderLayout.NORTH)
            add(center, BorderLayout.CENTER)
        }

        // Card 3: Dual-Path Self-Test
        val testCard = GlassCardPanel().apply {
            val wrapBtn = JPanel(GridBagLayout()).apply { isOpaque = false; add(btnLeakTest) }
            add(FreedomUiHelpers.sectionHeader("ÇİFT-YOL IP & SIZINTI DOĞRULAMA TESTİ", Color(56, 189, 248)), BorderLayout.NORTH)
            add(leakTestResult, BorderLayout.CENTER)
            add(wrapBtn, BorderLayout.EAST)
        }

        val c = GridBagConstraints().apply {
            gridx = 0
            weightx = 1.0
            fill = GridBagConstraints.BOTH
        }
        c.gridy = 0; c.weighty = 0.36; c.insets = Insets(0, 0, 10, 0); stack.add(browserCard, c)
        c.gridy = 1; c.weighty = 0.44; c.insets = Insets(0, 0, 10, 0); stack.add(personaCard, c)
        c.gridy = 2; c.weighty = 0.20; c.insets = Insets(0, 0, 0, 0); stack.add(testCard, c)
        return stack
    }
    private fun buildDiagWorkspace(): JPanel {
        val panel = JPanel(BorderLayout(0, 10)).apply {
            background = Color(7, 11, 20)
            border = BorderFactory.createEmptyBorder(14, 16, 10, 16)
        }
        val topCard = GlassCardPanel().apply {
            val presetBar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0)).apply {
                isOpaque = false
                add(
                    FreedomButton("Standart Set", arc = 7).apply {
                        addActionListener { targets.text = "cloudflare.com\nwikipedia.org\nietf.org" }
                    },
                )
                add(
                    FreedomButton("Discord + Sansür Seti", arc = 7).apply {
                        addActionListener { targets.text = "discord.com\ncloudflare.com\nwikipedia.org\nyoutube.com" }
                    },
                )
            }
            val form = JPanel(GridBagLayout()).apply { isOpaque = false }
            val c = GridBagConstraints().apply {
                insets = Insets(3, 4, 3, 4)
                anchor = GridBagConstraints.WEST
                fill = GridBagConstraints.HORIZONTAL
            }
            fun row(y: Int, label: String, comp: java.awt.Component) {
                val lbl = JLabel(label).apply {
                    foreground = Color(148, 163, 184)
                    font = Font("Segoe UI", Font.PLAIN, 11)
                }
                c.gridx = 0; c.gridy = y; c.weightx = 0.0; form.add(lbl, c)
                c.gridx = 1; c.weightx = 1.0; form.add(comp, c)
            }
            row(0, "Test hedefleri:", FreedomDarkTheme.darkScrollPane(targets))
            row(1, "Karşılaştırılacak DNS:", altDns)
            row(2, "Şifreli DoH adresleri:", dohEndpoints)

            val btnCopyDiag = FreedomButton(
                "Raporu Kopyala",
                fillColor = Color(30, 41, 59),
                textColor = Color(226, 232, 240),
                borderColor = Color(71, 85, 105),
                iconDrawer = SwingVectorIcons::drawCopy,
            ).apply {
                addActionListener {
                    FreedomUiHelpers.clipboardCopy(output.text, status, "Teşhis çıktısı panoya kopyalandı")
                }
            }
            val actionRow = JPanel(FlowLayout(FlowLayout.LEFT, 8, 2)).apply {
                isOpaque = false
                add(runButton)
                add(appliedButton)
                add(btnCopyDiag)
                add(auto)
            }
            add(FreedomUiHelpers.sectionHeader("AĞ TEŞHİS LABORATUVARI", Color(56, 189, 248), presetBar), BorderLayout.NORTH)
            add(form, BorderLayout.CENTER)
            add(actionRow, BorderLayout.SOUTH)
        }
        val telemetryBtns = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 0)).apply {
            isOpaque = false
            add(btnRefreshTelemetry)
            add(
                FreedomButton(
                    "Kopyala",
                    fillColor = Color(30, 41, 59),
                    textColor = Color(226, 232, 240),
                    borderColor = Color(71, 85, 105),
                    arc = 8,
                    iconDrawer = SwingVectorIcons::drawCopy,
                ).apply {
                    addActionListener {
                        FreedomUiHelpers.clipboardCopy(telemetryOutput.text, status, "Küresel gönüllü ağı telemetrisi panoya kopyalandı")
                    }
                },
            )
        }
        val reportCard = GlassCardPanel().apply {
            preferredSize = Dimension(640, 195)
            minimumSize = Dimension(320, 120)
            add(FreedomUiHelpers.sectionHeader("CANLI TEŞHİS RAPORU", Color(148, 163, 184)), BorderLayout.NORTH)
            add(FreedomDarkTheme.darkScrollPane(output), BorderLayout.CENTER)
        }
        val telemetryCard = GlassCardPanel().apply {
            preferredSize = Dimension(640, 145)
            minimumSize = Dimension(320, 95)
            add(FreedomUiHelpers.sectionHeader("KÜRESEL GÖNÜLLÜ AĞI (RIPE ATLAS · OONI · M-LAB)", Color(16, 185, 129), telemetryBtns), BorderLayout.NORTH)
            add(FreedomDarkTheme.darkScrollPane(telemetryOutput), BorderLayout.CENTER)
        }
        val splitReports = JPanel(GridBagLayout()).apply { isOpaque = false }
        val rc = GridBagConstraints().apply {
            gridx = 0
            weightx = 1.0
            fill = GridBagConstraints.BOTH
        }
        rc.gridy = 0; rc.weighty = 0.60; rc.insets = Insets(0, 0, 10, 0); splitReports.add(reportCard, rc)
        rc.gridy = 1; rc.weighty = 0.40; rc.insets = Insets(0, 0, 0, 0); splitReports.add(telemetryCard, rc)

        panel.add(topCard, BorderLayout.NORTH)
        panel.add(splitReports, BorderLayout.CENTER)
        return panel
    }

    private fun refreshTelemetry(silent: Boolean = false) {
        if (!telemetryBusy.compareAndSet(false, true)) return
        if (!silent) {
            btnRefreshTelemetry.isEnabled = false
            telemetryOutput.text = "RIPE Atlas, OONI, M-Lab ve Cloudflare canlı düğümleri ölçülüyor..."
        }
        worker.execute {
            try {
                val p = activeProxy
                val useProxy = p != null && p.isActive && p.localPort in 1..65535
                val snap = GlobalCensorshipTelemetry.collect(
                    countryCode = "TR",
                    proxyHost = if (useProxy) "127.0.0.1" else null,
                    proxyPort = if (useProxy) p!!.localPort else 0,
                    sslFactory = WindowsPlatform.trust.first,
                    timeoutMs = 4500,
                )
                val reportText = Text.telemetryReport(snap).trimEnd()
                ui {
                    telemetryOutput.text = reportText
                    telemetryOutput.caretPosition = 0
                    if (!silent) status.text = "Küresel gönüllü ağı telemetrisi güncellendi"
                }
            } catch (t: Throwable) {
                ui {
                    if (!silent || telemetryOutput.text.startsWith("Küresel gönüllü ağı")) {
                        telemetryOutput.text = "Küresel gönüllü ağı şu an erişilemedi: ${t.message}"
                    }
                }
            } finally {
                telemetryBusy.set(false)
                ui { btnRefreshTelemetry.isEnabled = true }
            }
        }
    }

    private fun buildLogWorkspace(): JPanel {
        val splitGrid = JPanel(GridLayout(2, 1, 0, 12)).apply {
            background = Color(7, 11, 20)
            border = BorderFactory.createEmptyBorder(14, 16, 10, 16)
        }

        val engineBtns = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 0)).apply {
            isOpaque = false
            add(
                FreedomButton("Günlüğü Temizle", arc = 8).apply {
                    addActionListener {
                        WindowsLogBus.clear()
                        lastLogVersion = -1L
                        motorLogOutput.text = "İç motor olay günlüğü temizlendi."
                    }
                },
            )
            add(
                FreedomButton("Kopyala", arc = 8, iconDrawer = SwingVectorIcons::drawCopy).apply {
                    addActionListener {
                        FreedomUiHelpers.clipboardCopy(motorLogOutput.text, status, "Motor olay günlüğü panoya kopyalandı")
                    }
                },
            )
        }
        val motorCard = GlassCardPanel().apply {
            add(FreedomUiHelpers.sectionHeader("CANLI İÇ MOTOR OLAY GÜNLÜĞÜ (WARP · DoH3 · TLS Bölme · Tarayıcı)", Color(56, 189, 248), engineBtns), BorderLayout.NORTH)
            add(FreedomDarkTheme.darkScrollPane(motorLogOutput), BorderLayout.CENTER)
        }

        val sysBtns = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 0)).apply {
            isOpaque = false
            add(systemButton)
            add(
                FreedomButton("Kopyala", arc = 8, iconDrawer = SwingVectorIcons::drawCopy).apply {
                    addActionListener {
                        FreedomUiHelpers.clipboardCopy(logOutput.text, status, "Sistem soket çıktısı panoya kopyalandı")
                    }
                },
            )
        }
        val sysCard = GlassCardPanel().apply {
            add(FreedomUiHelpers.sectionHeader("SİSTEM GENELİ BAĞLANTI GÖZLEMCİSİ", Color(16, 185, 129), sysBtns), BorderLayout.NORTH)
            add(FreedomDarkTheme.darkScrollPane(logOutput), BorderLayout.CENTER)
        }

        splitGrid.add(motorCard)
        splitGrid.add(sysCard)
        return splitGrid
    }

    private fun selectWorkspace(idx: Int) {
        activeWorkspaceIdx = idx.coerceIn(0, 3)
        navButtons.forEachIndexed { i, b ->
            val on = i == activeWorkspaceIdx
            b.background = if (on) Color(22, 42, 78) else Color(12, 19, 34)
            b.foreground = if (on) Color.WHITE else Color(148, 163, 184)
            b.borderColor = if (on) Color(56, 189, 248) else Color(26, 37, 56)
            b.repaint()
        }
        cardLayout.show(
            centerContainer,
            when (activeWorkspaceIdx) {
                0 -> "CONTROL"
                1 -> "PRIVACY"
                2 -> "DIAG"
                else -> "LOG"
            },
        )
    }

    private fun refreshModeButtons() {
        val items = listOf(
            WindowsRouteMode.AUTO_WARP to btnModeWarp,
            WindowsRouteMode.HYBRID_DPI to btnModeHybrid,
            WindowsRouteMode.CUSTOM_RELAY to btnModeRelay,
        )
        for ((mode, btn) in items) {
            val active = mode == selectedRouteMode
            btn.background = if (active) Color(6, 78, 59) else Color(15, 23, 42)
            btn.foreground = if (active) Color(167, 243, 208) else Color(148, 163, 184)
            btn.borderColor = if (active) Color(16, 185, 129) else Color(36, 48, 68)
            btn.repaint()
        }
        txtRelayUri.isEnabled = true
    }

    private fun selectRouteMode(mode: WindowsRouteMode) {
        val changed = selectedRouteMode != mode
        selectedRouteMode = mode
        refreshModeButtons()
        if (activeProxy?.isActive == true && changed) {
            pulsePanel.isConnecting = true
            status.text = "Çıkış rotası değiştiriliyor: ${mode.titleTr}..."
            worker.execute {
                proxyLock.lock()
                try {
                    stopActiveProxyLocked()
                    ensureProxyStartedLocked()
                } finally {
                    proxyLock.unlock()
                    ui { pulsePanel.isConnecting = false }
                }
            }
        } else {
            updateProtectionVisuals(activeProxy?.statusSnapshot(), mode.subtitleTr, activeProxy?.isIpMasked == true)
            status.text = "Seçili çıkış rotası: ${mode.titleTr}"
        }
    }

    private fun selectPersona(persona: DevicePersona) {
        selectedPersona = persona
        activeProxy?.updateSettings(devicePersona = persona)
        for ((p, btn) in personaButtons) {
            val on = p == persona
            btn.background = if (on) Color(46, 16, 101) else Color(15, 23, 42)
            btn.foreground = if (on) Color(233, 213, 255) else Color(148, 163, 184)
            btn.borderColor = if (on) Color(139, 92, 246) else Color(36, 48, 68)
            btn.repaint()
        }
        topPersonaPill.text = "Kimlik: ${persona.shortLabel}"
        status.text = "Cihaz kimliği: ${persona.shortLabel} (anında uygulandı)"
    }

    fun buildRootPanel(): JPanel {
        builtRoot?.let { return it }
        FreedomDarkTheme.ensureInstalled()

        centerContainer.add(buildControlWorkspace(), "CONTROL")
        centerContainer.add(buildPrivacyWorkspace(), "PRIVACY")
        centerContainer.add(buildDiagWorkspace(), "DIAG")
        centerContainer.add(buildLogWorkspace(), "LOG")

        val mainArea = JPanel(BorderLayout()).apply {
            background = Color(7, 11, 20)
            add(buildTelemetryStrip(), BorderLayout.NORTH)
            add(centerContainer, BorderLayout.CENTER)
            add(status.apply { border = BorderFactory.createEmptyBorder(4, 16, 8, 16) }, BorderLayout.SOUTH)
        }

        val root = JPanel(BorderLayout()).apply {
            background = Color(7, 11, 20)
            add(buildNavRail(), BorderLayout.WEST)
            add(mainArea, BorderLayout.CENTER)
        }

        wireUiActions()
        selectWorkspace(0)
        refreshModeButtons()
        selectPersona(selectedPersona)
        updateProtectionVisuals(null, selectedRouteMode.subtitleTr, false)

        builtRoot = root
        return root
    }

    internal fun buildRootPanelForTest(): JPanel = buildRootPanel()

    private fun wireUiActions() {
        pulsePanel.onToggleListener = { toggleDesync() }
        heroActionButton.addActionListener { toggleDesync() }
        btnModeWarp.addActionListener { selectRouteMode(WindowsRouteMode.AUTO_WARP) }
        btnModeHybrid.addActionListener { selectRouteMode(WindowsRouteMode.HYBRID_DPI) }
        btnModeRelay.addActionListener { selectRouteMode(WindowsRouteMode.CUSTOM_RELAY) }

        txtRelayUri.document.addDocumentListener(object : javax.swing.event.DocumentListener {
            private fun pushRelay() {
                activeProxy?.updateSettings(customRelayUri = txtRelayUri.text.trim())
            }
            override fun insertUpdate(e: javax.swing.event.DocumentEvent?) = pushRelay()
            override fun removeUpdate(e: javax.swing.event.DocumentEvent?) = pushRelay()
            override fun changedUpdate(e: javax.swing.event.DocumentEvent?) = pushRelay()
        })

        btnSystemProxyToggle.addActionListener {
            systemProxyDesired = !systemProxyDesired
            worker.execute {
                val p = activeProxy
                if (systemProxyDesired && p != null && p.isActive) {
                    WindowsSystemProxy.enable(p.localPort)
                } else {
                    WindowsSystemProxy.restore()
                }
                ui {
                    updateProtectionVisuals(p?.statusSnapshot(), p?.routeLabel ?: selectedRouteMode.subtitleTr, p?.isIpMasked == true)
                    status.text = if (systemProxyDesired) {
                        if (WindowsSystemProxy.appliedByApp) {
                            "Windows sistem vekili etkin (127.0.0.1:${p?.localPort})"
                        } else {
                            "Sistem vekili koruma başlatılınca otomatik uygulanacak"
                        }
                    } else {
                        "Windows sistem vekili orijinal ayarlara geri döndürüldü"
                    }
                }
            }
        }

        chkBlockTrackers.addActionListener {
            blockTrackersDesired = chkBlockTrackers.isSelected
            activeProxy?.updateSettings(blockTrackers = blockTrackersDesired)
        }
        chkStripUrlParams.addActionListener {
            stripUrlParamsDesired = chkStripUrlParams.isSelected
            activeProxy?.updateSettings(stripUrlParams = stripUrlParamsDesired)
        }
        chkBlockQuicLeaks.addActionListener {
            blockQuicLeaksDesired = chkBlockQuicLeaks.isSelected
            activeProxy?.updateSettings(blockQuicAndLeaks = blockQuicLeaksDesired)
        }

        btnVerifyIp.addActionListener { runDualIpCheck() }
        btnLeakTest.addActionListener { runDualIpCheck() }
        btnRefreshTelemetry.addActionListener { refreshTelemetry(silent = false) }
        btnLaunchBrowser.addActionListener { launchProtectedBrowser(null) }
        btnLaunchDiscord.addActionListener { launchProtectedBrowser("https://discord.com/") }
        btnQuickDiscord.addActionListener { launchProtectedBrowser("https://discord.com/") }

        runButton.addActionListener { startRun(verifyRuns = 0) }
        appliedButton.addActionListener { applied() }
        systemButton.addActionListener { showSystem() }
    }

    private fun loadWindowIcons() {
        val imgs = listOf("/icon-16.png", "/icon-32.png", "/icon-48.png", "/icon-256.png").mapNotNull { path ->
            runCatching { MainWindow::class.java.getResourceAsStream(path)?.use { ImageIO.read(it) } }.getOrNull()
        }
        if (imgs.isNotEmpty()) frame.iconImages = imgs
    }

    fun show() {
        val root = buildRootPanel()
        loadWindowIcons()
        frame.background = Color(7, 11, 20)
        frame.rootPane.background = Color(7, 11, 20)
        frame.contentPane = root
        frame.defaultCloseOperation = WindowConstants.DISPOSE_ON_CLOSE
        frame.addWindowListener(object : WindowAdapter() {
            override fun windowClosed(e: WindowEvent) = shutdown()
            override fun windowIconified(e: WindowEvent) {
                pulsePanel.setWindowMinimized(true)
                ticker.stop()
            }
            override fun windowDeiconified(e: WindowEvent) {
                pulsePanel.setWindowMinimized(false)
                ticker.start()
            }
        })
        frame.minimumSize = Dimension(960, 680)
        frame.size = Dimension(1080, 760)
        frame.setLocationRelativeTo(null)

        try {
            session = DiagnosticSession()
            status.text = "Motor ${Native.engineVersion()} hazır · TLS güveni: ${WindowsPlatform.trust.second}"
            watcher.start()
            ticker.start()
        } catch (e: NativeException) {
            runButton.isEnabled = false
            output.text = "Yerel motor başlatılamadı: ${e.message}"
        }
        refreshTelemetry(silent = true)
        frame.isVisible = true
    }

    private fun ui(block: () -> Unit) = SwingUtilities.invokeLater(block)

    private fun updateProtectionVisuals(ps: ProxyStatus?, routeText: String, ipMasked: Boolean) {
        val active = ps != null && ps.active
        if (active && ps != null) {
            sidebarStateBadge.text = "BAĞLI :${ps.port}"
            sidebarStateBadge.icon = SwingVectorIcons.asSwingIcon(FreedomIconId.SHIELD_CHECK, 12, Color(16, 185, 129))
            sidebarStateBadge.foreground = Color(167, 243, 208)
            sidebarStateBadge.background = Color(6, 78, 59)
            statusPill.text = "KORUMA AKTİF · 127.0.0.1:${ps.port}"
            statusPill.foreground = Color(16, 185, 129)
            heroActionButton.text = "KORUMAYI DURDUR (127.0.0.1:${ps.port})"
            heroActionButton.background = Color(220, 38, 38)
            heroActionButton.foreground = Color.WHITE
            heroActionButton.borderColor = Color(248, 113, 113)
            ipCardDetail.text = "$routeText · Port: 127.0.0.1:${ps.port}"
            topRoutePill.text = if (ipMasked) "Rota: $routeText (Maskeli)" else "Rota: $routeText"
            topRoutePill.foreground = if (ipMasked) Color(167, 243, 208) else Color(56, 189, 248)
        } else {
            sidebarStateBadge.text = "HAZIR"
            sidebarStateBadge.icon = SwingVectorIcons.asSwingIcon(FreedomIconId.SHIELD_OFF, 12, Color(148, 163, 184))
            sidebarStateBadge.foreground = Color(148, 163, 184)
            sidebarStateBadge.background = Color(15, 23, 42)
            statusPill.text = "KORUMA KAPALI · TEK TIKLA BAĞLANIN"
            statusPill.foreground = Color(148, 163, 184)
            heroActionButton.text = "ÖZGÜR AĞI BAŞLAT"
            heroActionButton.background = Color(16, 185, 129)
            heroActionButton.foreground = Color(4, 22, 16)
            heroActionButton.borderColor = Color(52, 211, 153)
            ipCardDetail.text = "Hazır · Seçili mod: ${selectedRouteMode.titleTr}"
            topRoutePill.text = "Rota: Hazır · ${selectedRouteMode.titleTr}"
            topRoutePill.foreground = Color(56, 189, 248)
        }
        ipCardDetail.toolTipText = ipCardDetail.text
        heroActionButton.repaint()

        if (WindowsSystemProxy.appliedByApp) {
            btnSystemProxyToggle.text = "WinINet Sistem Vekili: Açık"
            btnSystemProxyToggle.background = Color(6, 78, 59)
            btnSystemProxyToggle.foreground = Color(167, 243, 208)
            btnSystemProxyToggle.borderColor = Color(16, 185, 129)
            topSysProxyPill.text = "Sistem Vekili: Açık"
            topSysProxyPill.foreground = Color(167, 243, 208)
        } else if (systemProxyDesired) {
            btnSystemProxyToggle.text = "WinINet Sistem Vekili: Otomatik Açık"
            btnSystemProxyToggle.background = Color(15, 27, 46)
            btnSystemProxyToggle.foreground = Color(251, 191, 36)
            btnSystemProxyToggle.borderColor = Color(217, 119, 6)
            topSysProxyPill.text = "Sistem Vekili: Otomatik"
            topSysProxyPill.foreground = Color(251, 191, 36)
        } else {
            btnSystemProxyToggle.text = "WinINet Sistem Vekili: Kapalı"
            btnSystemProxyToggle.background = Color(15, 27, 46)
            btnSystemProxyToggle.foreground = Color(148, 163, 184)
            btnSystemProxyToggle.borderColor = Color(51, 65, 85)
            topSysProxyPill.text = "Sistem Vekili: Kapalı"
            topSysProxyPill.foreground = Color(148, 163, 184)
        }
        btnSystemProxyToggle.repaint()
    }

    private fun ensureProxyStartedLocked(): WindowsNextGenProxy {
        activeProxy?.let { if (it.isActive) return it }
        val customDoh = splitList(dohEndpoints.text).ifEmpty { TunBridge.DEFAULT_DOH_ENDPOINTS }
        val p = WindowsNextGenProxy(
            port = 0,
            routeMode = selectedRouteMode,
            customRelayUri = txtRelayUri.text.trim(),
            persona = selectedPersona,
            blockTrackers = blockTrackersDesired,
            stripUrlParams = stripUrlParamsDesired,
            blockQuicAndLeaks = blockQuicLeaksDesired,
            dohEndpoints = customDoh,
            onRouteUpdated = { label, masked ->
                ui {
                    val cur = activeProxy
                    if (cur != null && cur.isActive) {
                        updateProtectionVisuals(cur.statusSnapshot(), label, masked)
                    }
                }
            },
        )
        val bound = p.start()
        activeProxy = p
        if (bound > 0 && systemProxyDesired) {
            WindowsSystemProxy.enable(bound)
        }
        ui {
            val snap = p.statusSnapshot()
            pulsePanel.isConnecting = false
            pulsePanel.isActive = snap.active
            pulsePanel.portInfo = if (snap.active) "127.0.0.1:${snap.port}" else ""
            updateProtectionVisuals(snap, p.routeLabel, p.isIpMasked)
            status.text = "Freedom Network etkin (127.0.0.1:$bound · ${p.routeLabel})"
        }
        return p
    }

    private fun stopActiveProxyLocked() {
        runCatching { WindowsSystemProxy.restore() }
        runCatching { activeProxy?.close() }
        activeProxy = null
        ui {
            pulsePanel.isConnecting = false
            pulsePanel.isActive = false
            pulsePanel.portInfo = ""
            updateProtectionVisuals(null, selectedRouteMode.subtitleTr, false)
            status.text = "Freedom Network koruma motoru durduruldu"
        }
    }

    private fun toggleDesync() {
        heroActionButton.isEnabled = false
        if (activeProxy?.isActive != true) {
            pulsePanel.isConnecting = true
        }
        worker.execute {
            proxyLock.lock()
            try {
                if (activeProxy?.isActive == true) {
                    stopActiveProxyLocked()
                } else {
                    ensureProxyStartedLocked()
                }
            } catch (t: Throwable) {
                WindowsLogBus.append("Proxy", "Başlatma/durdurma hatası: ${t.message}")
                ui { status.text = "Motor hatası: ${t.message}" }
            } finally {
                proxyLock.unlock()
                ui {
                    pulsePanel.isConnecting = false
                    heroActionButton.isEnabled = true
                }
            }
        }
    }

    private fun launchProtectedBrowser(urlOverride: String?) {
        val rawUrl = (urlOverride ?: txtBrowserUrl.text).trim().ifBlank { "https://discord.com/" }
        val browserIdx = cmbBrowser.selectedIndex.coerceAtLeast(0)
        browserLaunchStatus.text = "Korumalı tarayıcı profili hazırlanıyor ($rawUrl)..."
        if (activeProxy?.isActive != true) {
            pulsePanel.isConnecting = true
        }
        worker.execute {
            proxyLock.lock()
            val port = try {
                val p = ensureProxyStartedLocked()
                p.localPort
            } catch (t: Throwable) {
                ui { browserLaunchStatus.text = "Motor başlatılamadı: ${t.message}" }
                0
            } finally {
                proxyLock.unlock()
                ui { pulsePanel.isConnecting = false }
            }
            if (port > 0) {
                val (ok, msg) = WindowsBrowserLauncher.launch(
                    proxyPort = port,
                    persona = selectedPersona,
                    initialUrl = rawUrl,
                    preferredBrowserIndex = browserIdx,
                    blockLocation = blockQuicLeaksDesired,
                )
                ui {
                    browserLaunchStatus.text = msg
                    browserLaunchStatus.foreground = if (ok) Color(167, 243, 208) else Color(251, 191, 36)
                    status.text = msg
                }
            }
        }
    }

    private fun runDualIpCheck() {
        btnLeakTest.isEnabled = false
        btnVerifyIp.isEnabled = false
        leakTestResult.text = "Doğrudan çıkış & yerel vekil yolu test ediliyor..."
        proxyIpLabel.text = "Tünel / Vekil Çıkışı: test ediliyor..."
        worker.execute {
            val sslFactory = WindowsPlatform.trust.first
            val directIp = runCatching {
                val conn = URI("https://api.ipify.org").toURL().openConnection(java.net.Proxy.NO_PROXY) as javax.net.ssl.HttpsURLConnection
                conn.sslSocketFactory = sslFactory
                conn.connectTimeout = 3500
                conn.readTimeout = 3500
                try {
                    conn.inputStream.bufferedReader().readText().trim()
                } finally {
                    conn.disconnect()
                }
            }.getOrNull()
            val p = activeProxy
            val proxyIp = if (p != null && p.isActive) {
                runCatching {
                    val proxy = java.net.Proxy(java.net.Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", p.localPort))
                    val conn = URI("https://api.ipify.org").toURL().openConnection(proxy) as javax.net.ssl.HttpsURLConnection
                    conn.sslSocketFactory = sslFactory
                    conn.connectTimeout = 5000
                    conn.readTimeout = 5000
                    try {
                        conn.inputStream.bufferedReader().readText().trim()
                    } finally {
                        conn.disconnect()
                    }
                }.getOrNull()
            } else null
            val wgReady = runCatching {
                Native.wgPublicKey(ByteArray(32).also { java.security.SecureRandom().nextBytes(it) })?.size == 32
            }.getOrDefault(false)
            ui {
                btnLeakTest.isEnabled = true
                btnVerifyIp.isEnabled = true
                directIpLabel.text = "Doğrudan Ağ IP: ${directIp ?: "ölçülemedi"}"
                proxyIpLabel.text = if (p?.isActive == true) {
                    "Tünel / Vekil (: ${p.localPort}): ${proxyIp ?: "zaman aşımı / ulaşılamadı"}"
                } else {
                    "Tünel / Vekil Çıkışı: koruma kapalı"
                }
                val summary = buildString {
                    append("Doğrudan IP: ").append(directIp ?: "ölçülemedi")
                    if (p?.isActive == true) {
                        append(" · Vekil (:").append(p.localPort).append("): ").append(proxyIp ?: "hata")
                        append(" · DoH=").append(p.dohResolved.get())
                        append(" · İzleyici=").append(p.trackersBlocked.get())
                        append(" · URL=").append(p.paramsStripped.get())
                    }
                    append(" · WG Kripto: ").append(if (wgReady) "Hazır" else "Hata")
                }
                leakTestResult.text = summary
                leakTestResult.toolTipText = summary
            }
        }
    }

    private fun startRun(verifyRuns: Int) {
        val s = session ?: return
        if (!busy.compareAndSet(false, true)) return
        val targetList = splitList(targets.text)
        val altList = splitList(altDns.text)
        val dohList = splitList(dohEndpoints.text)
        runButton.isEnabled = false
        appliedButton.isEnabled = false
        status.text = "Ağ tanılanıyor..."
        worker.execute {
            try {
                var remaining = verifyRuns + 1
                var text = ""
                while (remaining-- > 0) {
                    val env = refreshEnvironment(s)
                    val report = s.run(targetList, altList, WindowsPlatform.prober(), WindowsPlatform.dohClient(), dohList)
                    lastDecision = report.evaluation?.decision
                    text = Text.environment(env) + "\n" + Text.report(report)
                }
                ui {
                    output.text = text
                    output.caretPosition = 0
                    val d = lastDecision
                    appliedButton.isEnabled = d != null && d.state == 2 && d.action !in setOf(0, 8)
                    status.text = "Teşhis tamamlandı"
                }
            } catch (e: Exception) {
                ui { status.text = "Teşhis hatası: ${e.message}" }
            } finally {
                busy.set(false)
                ui { runButton.isEnabled = true }
            }
        }
    }

    private fun showSystem() {
        systemButton.isEnabled = false
        status.text = "Sistem bağlantıları okunuyor..."
        worker.execute {
            val text = try {
                Text.system(SystemSnapshot.capture())
            } catch (e: Exception) {
                "Sistem bağlantıları okunamadı: ${e.message}"
            }
            ui {
                logOutput.text = text
                logOutput.caretPosition = 0
                status.text = "Sistem geneli görünüm güncellendi"
                systemButton.isEnabled = true
            }
        }
    }

    private fun applied() {
        val s = session ?: return
        val d = lastDecision ?: return
        worker.execute {
            val rc = s.markApplied(d.action)
            ui {
                if (rc == Codes.OK) {
                    status.text = "Doğrulama başlatıldı: iki ölçüm yapılacak"
                    startRun(verifyRuns = 1)
                } else {
                    status.text = "Doğrulama başlatılamadı: ${Text.code(rc)}"
                }
            }
        }
    }

    private fun refreshEnvironment(s: DiagnosticSession): EnvironmentInfo {
        val env = WindowsPlatform.environment()
        val prev = lastEnv
        if (prev != null && prev.fingerprint() != env.fingerprint()) s.networkChanged()
        lastEnv = env
        s.setEnvironment(env)
        return env
    }

    private fun checkNetwork() {
        val s = session ?: return
        val prev = lastEnv ?: return
        if (busy.get()) return
        val env = WindowsPlatform.environment()
        if (prev.fingerprint() == env.fingerprint()) return
        s.networkChanged()
        lastEnv = env
        s.setEnvironment(env)
        ui {
            status.text = "Ağ değişti (${Text.networkType(env.networkType)} · ${env.interfaceName}); önceki sonuçlar geçersiz."
            appliedButton.isEnabled = false
            if (auto.isSelected) startRun(verifyRuns = 0)
        }
    }

    internal fun shutdown() {
        runCatching { WindowsSystemProxy.restore(asyncWinInet = true) }
        runCatching { activeProxy?.close() }
        activeProxy = null
        pulsePanel.stop()
        ticker.stop()
        watcher.stop()
        worker.shutdownNow()
        runCatching { worker.awaitTermination(2, TimeUnit.SECONDS) }
        session?.close()
        session = null
    }
}

fun main(args: Array<String>) {
    if (args.isNotEmpty()) exitProcess(runCli(args.toList()))
    FreedomDarkTheme.install()
    SwingUtilities.invokeLater { MainWindow().show() }
}
