package app.retunl.vpn

import io.nekohasekai.libbox.NetworkInterface as BoxInterface
import io.nekohasekai.libbox.NetworkInterfaceIterator
import io.nekohasekai.libbox.RoutePrefixIterator
import io.nekohasekai.libbox.RoutePrefix
import io.nekohasekai.libbox.StringIterator

/** Kotlin lists for libbox, which takes and gives Go-style iterators. */
class StringList(private val items: List<String>) : StringIterator {
    private var i = 0
    override fun hasNext() = i < items.size
    override fun len() = items.size
    override fun next(): String = items[i++]
}

class InterfaceList(private val items: List<BoxInterface>) : NetworkInterfaceIterator {
    private var i = 0
    override fun hasNext() = i < items.size
    override fun next(): BoxInterface = items[i++]
}

fun StringIterator?.toList(): List<String> {
    val out = mutableListOf<String>()
    if (this == null) return out
    while (hasNext()) next()?.let { out.add(it) }
    return out
}

fun RoutePrefixIterator?.toList(): List<RoutePrefix> {
    val out = mutableListOf<RoutePrefix>()
    if (this == null) return out
    while (hasNext()) next()?.let { out.add(it) }
    return out
}
