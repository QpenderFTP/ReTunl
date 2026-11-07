package app.retunl.vpn

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.Drawable
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.util.Base64
import android.webkit.WebView
import androidx.activity.ComponentActivity
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.ActivityResult
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.view.WindowCompat
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSArray
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import io.nekohasekai.libbox.Libbox
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.util.concurrent.Executors

@InvokeArg
class StartArgs {
    lateinit var id: String
    lateinit var config: String
    var vpn: Boolean = false
}

@InvokeArg
class IdArgs {
    lateinit var id: String
}

@InvokeArg
class CheckArgs {
    lateinit var config: String
}

@InvokeArg
class UrlArgs {
    lateinit var url: String
}

@InvokeArg
class BarsArgs {
    var dark: Boolean = false
}

@InvokeArg
class IconArgs {
    var packages: Array<String> = emptyArray()
}

/**
 * What ReTunl's Rust code calls (see crates/vpn-android/src/lib.rs).
 * Commands arrive on the UI thread: slow ones move to [work].
 */
@TauriPlugin
class VpnPlugin(private val activity: Activity) : Plugin(activity) {
    @Volatile private var waiting: StartArgs? = null
    private val work = Executors.newCachedThreadPool()

    private fun background(invoke: Invoke, f: () -> Unit) {
        work.execute {
            try {
                f()
            } catch (e: Exception) {
                invoke.reject(e.message ?: e.toString())
            }
        }
    }

    init {
        Boxes.setup(activity.applicationContext)
    }

    /**
     * Android's «Назад»: the page closes a dialog or a menu, or goes to Обзор
     * (window.retunlBack returns "done"); otherwise ReTunl goes to the background
     * like Home. Finishing the activity would end the UI process.
     */
    override fun load(webView: WebView) {
        val owner = activity as? ComponentActivity ?: return
        owner.runOnUiThread {
            owner.onBackPressedDispatcher.addCallback(owner, object : OnBackPressedCallback(true) {
                override fun handleOnBackPressed() {
                    webView.evaluateJavascript("window.retunlBack ? window.retunlBack() : ''") { r ->
                        if (r != "\"done\"") owner.moveTaskToBack(true)
                    }
                }
            })
        }
    }

    @Command
    fun start(invoke: Invoke) {
        val args = invoke.parseArgs(StartArgs::class.java)
        try {
            if (!args.vpn) {
                background(invoke) {
                    Boxes.startPlain(args.id, args.config)
                    invoke.resolve(JSObject())
                }
                return
            }
            val ask = VpnService.prepare(activity)
            if (ask == null) {
                startVpn(invoke, args)
                return
            }
            waiting = args
            activity.runOnUiThread { startActivityForResult(invoke, ask, "vpnAllowed") }
        } catch (e: Exception) {
            invoke.reject(e.message ?: e.toString())
        }
    }

    @ActivityCallback
    fun vpnAllowed(invoke: Invoke, result: ActivityResult) {
        val args = waiting
        waiting = null
        if (result.resultCode != Activity.RESULT_OK || args == null) {
            invoke.reject("Вы не разрешили VPN-подключение. ReTunl работает только через VPN Android.")
            return
        }
        startVpn(invoke, args)
    }

    private fun startVpn(invoke: Invoke, args: StartArgs) {
        askPermissionsOnce()
        try {
            Boxes.startVpn(args.id, args.config)
            invoke.resolve(JSObject())
        } catch (e: Exception) {
            invoke.reject(e.message ?: e.toString())
        }
    }

    /**
     * Asked once each, on the first connection; the VPN starts either way.
     * Android 13+: the "connected" notification. Android 17+: the home network,
     * without it sing-box cannot reach the router, a NAS or a server at home.
     */
    private fun askPermissionsOnce() {
        val wanted = mutableListOf<String>()
        if (Build.VERSION.SDK_INT >= 33) wanted += Manifest.permission.POST_NOTIFICATIONS
        if (Build.VERSION.SDK_INT >= 37) wanted += LOCAL_NETWORK
        val prefs = activity.getSharedPreferences("retunl-vpn", 0)
        val ask = wanted.filter {
            ContextCompat.checkSelfPermission(activity, it) != PackageManager.PERMISSION_GRANTED &&
                !prefs.getBoolean("asked:$it", false)
        }
        if (ask.isEmpty()) return
        prefs.edit().apply { ask.forEach { putBoolean("asked:$it", true) } }.apply()
        activity.runOnUiThread {
            ActivityCompat.requestPermissions(activity, ask.toTypedArray(), 7101)
        }
    }

    private companion object {
        const val LOCAL_NETWORK = "android.permission.ACCESS_LOCAL_NETWORK"
    }

    @Command
    fun stop(invoke: Invoke) = background(invoke) {
        val args = invoke.parseArgs(IdArgs::class.java)
        Boxes.stop(args.id)
        invoke.resolve(JSObject())
    }

    @Command
    fun status(invoke: Invoke) {
        val args = invoke.parseArgs(IdArgs::class.java)
        val s = Boxes.status(args.id)
        val out = JSObject()
        out.put("state", s.state)
        out.put("error", s.error ?: JSONObject.NULL)
        invoke.resolve(out)
    }

    @Command
    fun check(invoke: Invoke) {
        val args = invoke.parseArgs(CheckArgs::class.java)
        background(invoke) {
            Libbox.checkConfig(args.config)
            invoke.resolve(JSObject())
        }
    }

    @Command
    fun version(invoke: Invoke) {
        val out = JSObject()
        out.put("version", Boxes.version())
        invoke.resolve(out)
    }

    /** Apps that may use the network, for rules. */
    @Command
    fun apps(invoke: Invoke) = background(invoke) {
        val pm = activity.packageManager
        val list = JSArray()
        @Suppress("DEPRECATION")
        for (ai in pm.getInstalledApplications(0)) {
            if (ai.packageName == activity.packageName) continue
            if (pm.checkPermission(Manifest.permission.INTERNET, ai.packageName) != PackageManager.PERMISSION_GRANTED) continue
            val launchable = pm.getLaunchIntentForPackage(ai.packageName) != null
            val builtIn = (ai.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0
            val item = JSObject()
            item.put("package", ai.packageName)
            item.put("label", runCatching { ai.loadLabel(pm).toString() }.getOrDefault(ai.packageName))
            // Chrome on many phones is built in, but people open it: only hidden services count as system
            item.put("system", builtIn && !launchable)
            list.put(item)
        }
        val out = JSObject()
        out.put("apps", list)
        invoke.resolve(out)
    }

    @Command
    fun icons(invoke: Invoke) = background(invoke) {
        val args = invoke.parseArgs(IconArgs::class.java)
        val pm = activity.packageManager
        val icons = JSObject()
        for (p in args.packages) {
            val data = runCatching { png(pm.getApplicationIcon(p)) }.getOrNull()
            icons.put(p, data ?: JSONObject.NULL)
        }
        val out = JSObject()
        out.put("icons", icons)
        invoke.resolve(out)
    }

    @Command
    fun bars(invoke: Invoke) {
        val args = invoke.parseArgs(BarsArgs::class.java)
        activity.runOnUiThread {
            val bars = WindowCompat.getInsetsController(activity.window, activity.window.decorView)
            bars.isAppearanceLightStatusBars = !args.dark
            bars.isAppearanceLightNavigationBars = !args.dark
        }
        invoke.resolve(JSObject())
    }

    @Command
    fun openUrl(invoke: Invoke) {
        val args = invoke.parseArgs(UrlArgs::class.java)
        try {
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(args.url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            activity.startActivity(intent)
            invoke.resolve(JSObject())
        } catch (e: Exception) {
            invoke.reject("Не нашлось браузера, чтобы открыть ссылку")
        }
    }

    private fun png(d: Drawable): String {
        val size = 96
        val bmp = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
        d.setBounds(0, 0, size, size)
        d.draw(Canvas(bmp))
        val bytes = ByteArrayOutputStream().use { s ->
            bmp.compress(Bitmap.CompressFormat.PNG, 100, s)
            s.toByteArray()
        }
        return "data:image/png;base64," + Base64.encodeToString(bytes, Base64.NO_WRAP)
    }
}
