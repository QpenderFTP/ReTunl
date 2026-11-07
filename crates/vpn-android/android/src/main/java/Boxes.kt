package app.retunl.vpn

import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import androidx.core.content.ContextCompat
import io.nekohasekai.libbox.CommandServer
import io.nekohasekai.libbox.CommandServerHandler
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.OverrideOptions
import io.nekohasekai.libbox.SetupOptions
import io.nekohasekai.libbox.SystemProxyStatus
import java.io.File
import java.util.concurrent.ConcurrentHashMap

/**
 * sing-box instances, by id. Test instances (latency, speed) run right here,
 * in the app's process, without a tunnel. The main connection runs in
 * [RetunlVpnService], in its own process: this side starts and stops it with
 * intents and reads its state from [VpnState].
 */
object Boxes {
    class State(val state: String, val error: String? = null)

    private val states = ConcurrentHashMap<String, State>()
    private val servers = ConcurrentHashMap<String, CommandServer>()
    private var ready = false
    private lateinit var app: Context

    /** Set in the VPN process while the service runs. */
    @Volatile var vpnService: RetunlVpnService? = null

    /** `dir`: each process keeps its own libbox files. */
    @Synchronized
    fun setup(ctx: Context, dir: String = "libbox") {
        if (ready) return
        app = ctx.applicationContext
        Net.init(app)
        val base = File(app.filesDir, dir).apply { mkdirs() }
        Libbox.setup(SetupOptions().also {
            it.basePath = base.path
            it.workingPath = base.path
            it.tempPath = app.cacheDir.path
            // as in sing-box for Android
            it.fixAndroidStack = Build.VERSION.SDK_INT in 24..25 || Build.VERSION.SDK_INT >= 28
            it.logMaxLines = 500
            it.debug = false
        })
        ready = true
    }

    fun version(): String = Libbox.version()

    fun status(id: String): State {
        states[id]?.let { return it }
        val v = VpnState.read(app)?.takeIf { it.id == id } ?: return State("none")
        if (v.live && !VpnState.processAlive(app)) {
            // a moment to come up after the start; after that a missing process means it is gone
            val starting = v.state == "starting" && System.currentTimeMillis() - v.at < 15_000
            if (!starting) {
                val why = "VPN-служба Android завершилась."
                VpnState.write(app, id, "failed", why)
                return State("failed", why)
            }
        }
        return State(v.state, v.error)
    }

    /** A test instance: no tunnel, started before this returns. */
    fun startPlain(id: String, config: String) {
        stop(id)
        states[id] = State("starting")
        val server = Libbox.newCommandServer(Handler { stop(id) }, Platform(app, null))
        servers[id] = server
        try {
            server.startOrReloadService(config, OverrideOptions())
            states[id] = State("running")
        } catch (e: Exception) {
            servers.remove(id)
            close(server)
            states[id] = State("failed", message(e))
            throw Exception(message(e))
        }
    }

    /** The VPN: hands the config to the service, which starts in its own process. */
    fun startVpn(id: String, config: String) {
        VpnState.config(app).writeText(config)
        VpnState.write(app, id, "starting")
        val intent = Intent(app, RetunlVpnService::class.java)
            .setAction(RetunlVpnService.ACTION_START)
            .putExtra(RetunlVpnService.EXTRA_ID, id)
        ContextCompat.startForegroundService(app, intent)
    }

    fun stop(id: String) {
        val server = servers.remove(id)
        if (server != null || states.containsKey(id)) {
            server?.let { close(it) }
            val was = states[id]?.state
            if (was == "starting" || was == "running") states[id] = State("stopped")
            return
        }
        val v = VpnState.read(app)?.takeIf { it.id == id && it.live } ?: return
        val intent = Intent(app, RetunlVpnService::class.java)
            .setAction(RetunlVpnService.ACTION_STOP)
            .putExtra(RetunlVpnService.EXTRA_ID, v.id)
        // Android may refuse to start a service from the background: then the process is gone anyway
        runCatching { app.startService(intent) }.onFailure {
            Log.w("ReTunl", "stop: ${it.message}")
            if (!VpnState.processAlive(app)) VpnState.write(app, id, "stopped")
        }
    }

    internal fun close(server: CommandServer) {
        runCatching { server.closeService() }
        runCatching { server.close() }
    }

    internal fun message(e: Throwable): String = e.message?.takeIf { it.isNotBlank() } ?: e.toString()

    /** What sing-box asks of the app; `onStop`: it wants to stop (not on its own thread). */
    internal class Handler(private val onStop: () -> Unit) : CommandServerHandler {
        override fun connectSSHAgent(): Int = throw UnsupportedOperationException()
        override fun getSystemProxyStatus(): SystemProxyStatus = SystemProxyStatus()
        override fun serviceReload() {}
        override fun serviceStop() {
            Thread { onStop() }.start()
        }
        override fun setSystemProxyEnabled(isEnabled: Boolean) {}
        override fun triggerNativeCrash() {}
        override fun writeDebugMessage(message: String?) {
            Log.d("ReTunl", message ?: "")
        }
    }
}
