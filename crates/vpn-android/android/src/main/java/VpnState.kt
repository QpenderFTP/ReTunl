package app.retunl.vpn

import android.app.ActivityManager
import android.content.Context
import org.json.JSONObject
import java.io.File

/**
 * The main connection as both processes see it. The VPN service runs in its
 * own process (":vpn"), so closing ReTunl's window, or Android ending the
 * app's process, leaves the VPN on. The service writes its state to a small
 * file; the app reads it, and the next ReTunl window picks the connection up.
 */
internal object VpnState {
    class Value(val id: String, val state: String, val error: String?, val at: Long) {
        val live get() = state == "starting" || state == "running"
    }

    fun dir(ctx: Context) = File(ctx.filesDir, "vpn").apply { mkdirs() }

    /** The config the service runs: too big for an Intent. */
    fun config(ctx: Context) = File(dir(ctx), "config.json")

    private fun file(ctx: Context) = File(dir(ctx), "state.json")

    @Synchronized
    fun write(ctx: Context, id: String, state: String, error: String? = null) {
        val o = JSONObject()
            .put("id", id)
            .put("state", state)
            .put("error", error ?: JSONObject.NULL)
            .put("at", System.currentTimeMillis())
        val tmp = File(dir(ctx), "state.json.tmp")
        tmp.writeText(o.toString())
        tmp.renameTo(file(ctx))
    }

    fun read(ctx: Context): Value? = runCatching {
        val o = JSONObject(file(ctx).readText())
        Value(
            o.getString("id"),
            o.getString("state"),
            if (o.isNull("error")) null else o.getString("error"),
            o.optLong("at"),
        )
    }.getOrNull()

    /** Is the VPN service's process running at all? */
    fun processAlive(ctx: Context): Boolean {
        val name = ctx.packageName + ":vpn"
        val am = ctx.getSystemService(ActivityManager::class.java)
        return am.runningAppProcesses?.any { it.processName == name } == true
    }
}
