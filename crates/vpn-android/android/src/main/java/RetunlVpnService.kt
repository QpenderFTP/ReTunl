package app.retunl.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import io.nekohasekai.libbox.CommandServer
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.OverrideOptions
import java.util.concurrent.Executors

/**
 * The main connection. Runs in its own process (":vpn"): it holds the tunnel
 * and sing-box, and outlives ReTunl's window. Starts and stops one at a time,
 * in order, on [work]; reports its state through [VpnState].
 */
class RetunlVpnService : VpnService() {
    companion object {
        const val ACTION_START = "app.retunl.vpn.START"
        const val ACTION_STOP = "app.retunl.vpn.STOP"
        const val EXTRA_ID = "id"
        private const val CHANNEL = "vpn"
        private const val NOTE = 1
    }

    @Volatile var tun: ParcelFileDescriptor? = null
    private val work = Executors.newSingleThreadExecutor()
    private var server: CommandServer? = null
    private var current: String? = null
    @Volatile private var finished = true

    override fun onCreate() {
        super.onCreate()
        Boxes.setup(applicationContext, "libbox-vpn")
        Boxes.vpnService = this
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val id = intent?.getStringExtra(EXTRA_ID)
        when (intent?.action) {
            ACTION_START -> {
                // started with startForegroundService: in the foreground right away
                finished = false
                foreground(connected = false)
                if (id != null) work.execute { start(id) } else work.execute { stop(null, null) }
            }
            // «Отключить» in the notification has no id: whatever runs
            else -> work.execute { stop(id, null) }
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        work.execute { stop(null, "VPN выключили в настройках Android, или его занял другой VPN.") }
    }

    override fun onDestroy() {
        current?.let { VpnState.write(this, it, "failed", "Android остановил VPN-службу.") }
        server?.let { Boxes.close(it) }
        server = null
        current = null
        if (Boxes.vpnService === this) Boxes.vpnService = null
        closeTun()
        work.shutdownNow()
        super.onDestroy()
    }

    private fun start(id: String) {
        server?.let { Boxes.close(it) }
        server = null
        current = id
        try {
            val config = VpnState.config(this).readText()
            val s = Libbox.newCommandServer(Boxes.Handler { later { stop(id, null) } }, Platform(applicationContext, this))
            server = s
            s.startOrReloadService(config, OverrideOptions())
            VpnState.write(this, id, "running")
            foreground(connected = true)
        } catch (e: Exception) {
            Log.e("ReTunl", "start failed", e)
            server?.let { Boxes.close(it) }
            server = null
            current = null
            VpnState.write(this, id, "failed", Boxes.message(e))
            finish()
        }
    }

    /** `id`: stop only that connection (null: whatever runs). `reason` makes it a failure. */
    private fun stop(id: String?, reason: String?) {
        val running = current
        if (id != null && running != null && id != running) return
        server?.let { Boxes.close(it) }
        server = null
        current = null
        val which = running ?: id
        if (which != null && VpnState.read(this)?.let { it.id == which && it.live } == true) {
            VpnState.write(this, which, if (reason != null) "failed" else "stopped", reason)
        }
        finish()
    }

    /** After the service is gone the queue refuses work: nothing is left to stop then. */
    private fun later(f: () -> Unit) {
        runCatching { work.execute(f) }
    }

    private fun finish() {
        if (finished) {
            stopSelf()
            return
        }
        finished = true
        closeTun()
        if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_REMOVE) else @Suppress("DEPRECATION") stopForeground(true)
        stopSelf()
    }

    private fun closeTun() {
        runCatching { tun?.close() }
        tun = null
    }

    private fun foreground(connected: Boolean) {
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL, "VPN-подключение", NotificationManager.IMPORTANCE_LOW).apply {
                    description = "Показывается, пока ReTunl подключён"
                    setShowBadge(false)
                }
            )
        }
        val open = packageManager.getLaunchIntentForPackage(packageName)?.let {
            PendingIntent.getActivity(this, 0, it, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        }
        val stop = PendingIntent.getService(
            this, 1, Intent(this, RetunlVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val n: Notification = NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_retunl_vpn)
            .setContentTitle(if (connected) "ReTunl подключён" else "ReTunl подключается…")
            .setContentIntent(open)
            .setOngoing(true)
            .setShowWhen(false)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .addAction(0, "Отключить", stop)
            .build()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTE, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTE, n)
        }
    }
}
