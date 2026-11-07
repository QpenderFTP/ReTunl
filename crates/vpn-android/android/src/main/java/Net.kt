package app.retunl.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.system.OsConstants
import io.nekohasekai.libbox.InterfaceUpdateListener
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.NetworkInterface as BoxInterface
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * The phone's real network (Wi-Fi, mobile), never our own VPN: sing-box
 * binds its sockets to it. One system callback serves every running instance.
 */
object Net {
    private lateinit var cm: ConnectivityManager
    private val listeners = CopyOnWriteArrayList<InterfaceUpdateListener>()
    private var callback: ConnectivityManager.NetworkCallback? = null
    private val thread by lazy { HandlerThread("retunl-net").apply { start() } }
    @Volatile private var first = CountDownLatch(1)
    @Volatile var network: Network? = null
        private set

    fun init(ctx: Context) {
        if (!::cm.isInitialized) cm = ctx.getSystemService(ConnectivityManager::class.java)
    }

    @Synchronized
    fun add(listener: InterfaceUpdateListener) {
        listeners.add(listener)
        if (callback == null) register()
        // sing-box needs the interface right away: wait a moment for the first answer
        first.await(2, TimeUnit.SECONDS)
        tell(listener, network)
    }

    @Synchronized
    fun remove(listener: InterfaceUpdateListener) {
        listeners.remove(listener)
        if (listeners.isEmpty()) {
            callback?.let { runCatching { cm.unregisterNetworkCallback(it) } }
            callback = null
            network = null
            first = CountDownLatch(1)
        }
    }

    private fun register() {
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(n: Network) = changed(n)
            override fun onCapabilitiesChanged(n: Network, caps: NetworkCapabilities) {
                if (n == network) changed(n)
            }
            override fun onLinkPropertiesChanged(n: Network, lp: LinkProperties) {
                if (n == network) changed(n)
            }
            override fun onLost(n: Network) {
                if (n == network) changed(null)
            }
        }
        // the default request already leaves VPNs out (NOT_VPN)
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
            .build()
        val handler = Handler(thread.looper)
        when {
            Build.VERSION.SDK_INT >= 31 -> cm.registerBestMatchingNetworkCallback(request, cb, handler)
            Build.VERSION.SDK_INT >= 28 -> cm.requestNetwork(request, cb, handler)
            else -> cm.registerDefaultNetworkCallback(cb, handler)
        }
        callback = cb
    }

    private fun changed(n: Network?) {
        network = n
        Boxes.vpnService?.let { s -> runCatching { s.setUnderlyingNetworks(n?.let { arrayOf(it) }) } }
        for (l in listeners) tell(l, n)
        first.countDown()
    }

    private fun tell(l: InterfaceUpdateListener, n: Network?) {
        val name = n?.let { cm.getLinkProperties(it)?.interfaceName }
        if (n == null || name == null) {
            runCatching { l.updateDefaultInterface("", -1, false, false) }
            return
        }
        // the index can lag right after a network appears
        var index = -1
        for (i in 0 until 10) {
            index = runCatching { java.net.NetworkInterface.getByName(name)?.index ?: -1 }.getOrDefault(-1)
            if (index >= 0) break
            Thread.sleep(100)
        }
        val caps = cm.getNetworkCapabilities(n)
        val metered = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) == false
        runCatching { l.updateDefaultInterface(name, index, metered, false) }
    }

    /** Every network the phone has, for sing-box's interface list. */
    @Suppress("DEPRECATION")
    fun interfaces(): List<BoxInterface> {
        val out = mutableListOf<BoxInterface>()
        for (n in cm.allNetworks) {
            val lp = cm.getLinkProperties(n) ?: continue
            val caps = cm.getNetworkCapabilities(n) ?: continue
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
            val name = lp.interfaceName ?: continue
            val ni = runCatching { java.net.NetworkInterface.getByName(name) }.getOrNull() ?: continue
            val item = BoxInterface()
            item.setName(name)
            item.setIndex(ni.index)
            item.setMTU(runCatching { ni.mtu }.getOrDefault(1500))
            item.setAddresses(StringList(lp.linkAddresses.mapNotNull { a ->
                a.address.hostAddress?.substringBefore('%')?.let { "$it/${a.prefixLength}" }
            }))
            var flags = 0
            if (runCatching { ni.isUp }.getOrDefault(false)) flags = flags or OsConstants.IFF_UP or OsConstants.IFF_RUNNING
            if (runCatching { ni.isLoopback }.getOrDefault(false)) flags = flags or OsConstants.IFF_LOOPBACK
            if (runCatching { ni.isPointToPoint }.getOrDefault(false)) flags = flags or OsConstants.IFF_POINTOPOINT
            if (runCatching { ni.supportsMulticast() }.getOrDefault(false)) flags = flags or OsConstants.IFF_MULTICAST
            item.setFlags(flags)
            item.setType(
                when {
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> Libbox.InterfaceTypeWIFI
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> Libbox.InterfaceTypeCellular
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> Libbox.InterfaceTypeEthernet
                    else -> Libbox.InterfaceTypeOther
                }
            )
            item.setDNSServer(StringList(lp.dnsServers.mapNotNull { it.hostAddress }))
            item.setMetered(!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED))
            out.add(item)
        }
        return out
    }
}
