package app.retunl.vpn

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.IpPrefix
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Process
import android.util.Log
import io.nekohasekai.libbox.BridgeOptions
import io.nekohasekai.libbox.BridgeSession
import io.nekohasekai.libbox.ConnectionOwner
import io.nekohasekai.libbox.InterfaceUpdateListener
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.LocalDNSTransport
import io.nekohasekai.libbox.NeighborUpdateListener
import io.nekohasekai.libbox.NetworkInterfaceIterator
import io.nekohasekai.libbox.Notification
import io.nekohasekai.libbox.PlatformInterface
import io.nekohasekai.libbox.PlatformUser
import io.nekohasekai.libbox.RoutePrefix
import io.nekohasekai.libbox.ShellSession
import io.nekohasekai.libbox.StringIterator
import io.nekohasekai.libbox.TunOptions
import io.nekohasekai.libbox.WIFIState
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * What sing-box asks of Android. `vpn` is set for the main connection only
 * (in the VPN process); test instances have no tunnel, and their sockets
 * skip a running VPN.
 */
class Platform(private val ctx: Context, private val vpn: RetunlVpnService?) : PlatformInterface {
    private val cm = ctx.getSystemService(ConnectivityManager::class.java)

    override fun openTun(options: TunOptions): Int {
        val service = vpn ?: error("this instance has no VPN")
        val b = service.Builder().setSession("ReTunl").setMtu(options.mtu)
        if (Build.VERSION.SDK_INT >= 29) b.setMetered(false)
        val v4 = options.inet4Address.toList()
        val v6 = options.inet6Address.toList()
        for (a in v4 + v6) b.addAddress(a.address(), a.prefix())
        if (options.autoRoute) {
            for (dns in options.dnsServerAddress.toList()) b.addDnsServer(dns)
            if (Build.VERSION.SDK_INT >= 33) {
                val r4 = options.inet4RouteAddress.toList()
                if (r4.isNotEmpty()) r4.forEach { b.addRoute(it.ipPrefix()) } else if (v4.isNotEmpty()) b.addRoute("0.0.0.0", 0)
                val r6 = options.inet6RouteAddress.toList()
                if (r6.isNotEmpty()) r6.forEach { b.addRoute(it.ipPrefix()) } else if (v6.isNotEmpty()) b.addRoute("::", 0)
                options.inet4RouteExcludeAddress.toList().forEach { b.excludeRoute(it.ipPrefix()) }
                options.inet6RouteExcludeAddress.toList().forEach { b.excludeRoute(it.ipPrefix()) }
            } else {
                // older Android cannot exclude: sing-box gives the remaining ranges
                options.inet4RouteRange.toList().forEach { b.addRoute(it.address(), it.prefix()) }
                options.inet6RouteRange.toList().forEach { b.addRoute(it.address(), it.prefix()) }
            }
            for (p in options.includePackage.toList()) {
                try { b.addAllowedApplication(p) } catch (_: PackageManager.NameNotFoundException) {}
            }
            for (p in options.excludePackage.toList()) {
                try { b.addDisallowedApplication(p) } catch (_: PackageManager.NameNotFoundException) {}
            }
        }
        Net.network?.let { b.setUnderlyingNetworks(arrayOf(it)) }
        val pfd = b.establish() ?: error("Android не открыл VPN: нет разрешения или его забрал другой VPN")
        service.tun = pfd
        return pfd.fd
    }

    private fun RoutePrefix.ipPrefix(): IpPrefix =
        if (Build.VERSION.SDK_INT >= 33) IpPrefix(InetAddress.getByName(address()), prefix())
        else error("unreachable")

    // sockets of sing-box itself must not loop back into our own tunnel
    override fun usePlatformAutoDetectInterfaceControl() = true

    override fun autoDetectInterfaceControl(fd: Int) {
        if (vpn != null) {
            if (!vpn.protect(fd)) error("protect($fd) failed")
            return
        }
        // a test instance, in the app's process: straight to the phone's network, past our VPN
        val network = Net.network ?: return
        val copy = ParcelFileDescriptor.fromFd(fd)
        try {
            network.bindSocket(copy.fileDescriptor)
        } finally {
            copy.close()
        }
    }

    override fun findConnectionOwner(
        ipProtocol: Int, sourceAddress: String, sourcePort: Int, destinationAddress: String, destinationPort: Int,
    ): ConnectionOwner {
        if (Build.VERSION.SDK_INT < 29) {
            return Libbox.findConnectionOwner(ipProtocol, sourceAddress, sourcePort, destinationAddress, destinationPort)
        }
        val uid = cm.getConnectionOwnerUid(
            ipProtocol,
            InetSocketAddress(InetAddress.getByName(sourceAddress), sourcePort),
            InetSocketAddress(InetAddress.getByName(destinationAddress), destinationPort),
        )
        if (uid == Process.INVALID_UID) error("connection owner not found")
        val pm = ctx.packageManager
        val owner = ConnectionOwner()
        owner.setUserId(uid)
        owner.setUserName(pm.getNameForUid(uid) ?: "")
        owner.setAndroidPackageNames(StringList(pm.getPackagesForUid(uid)?.toList() ?: emptyList()))
        return owner
    }

    override fun startDefaultInterfaceMonitor(listener: InterfaceUpdateListener) = Net.add(listener)
    override fun closeDefaultInterfaceMonitor(listener: InterfaceUpdateListener) = Net.remove(listener)
    override fun getInterfaces(): NetworkInterfaceIterator = InterfaceList(Net.interfaces())

    override fun underNetworkExtension() = false
    override fun includeAllNetworks() = false
    override fun clearDNSCache() {}
    override fun readWIFIState(): WIFIState? = null
    override fun localDNSTransport(): LocalDNSTransport? = null
    override fun registerMyInterface(name: String?) {}

    override fun sendNotification(notification: Notification) {
        Log.i("ReTunl", "sing-box: ${notification.title}: ${notification.body}")
    }
    override fun cancelNotification(identifier: String?, typeId: Int) {}

    // remote shells, bridges, Tailscale and the rest are not used by ReTunl
    override fun usePlatformShell() = false
    override fun checkPlatformShell() = throw UnsupportedOperationException()
    override fun openShellSession(
        user: PlatformUser?, command: String?, args: StringIterator?, workingDir: String?, rows: Int, cols: Int,
    ): ShellSession = throw UnsupportedOperationException()
    override fun lookupUser(name: String?): PlatformUser = throw UnsupportedOperationException()
    override fun lookupSFTPServer(): String = throw UnsupportedOperationException()
    override fun readSystemSSHHostKey(): String = throw UnsupportedOperationException()
    override fun tailscaleHostname() = "retunl"
    override fun usePlatformBridge() = false
    override fun createBridge(options: BridgeOptions?): BridgeSession = throw UnsupportedOperationException()
    override fun startNeighborMonitor(listener: NeighborUpdateListener?) {}
    override fun closeNeighborMonitor(listener: NeighborUpdateListener?) {}
}
