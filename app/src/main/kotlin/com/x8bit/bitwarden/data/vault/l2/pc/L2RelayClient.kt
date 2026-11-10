package com.x8bit.bitwarden.data.vault.l2.pc

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.net.URI
import java.util.concurrent.TimeUnit

private const val PING_SECONDS = 20L
private const val HTTP_CREATED = 201

/** A frame the relay delivered to this phone (PROTOCOL.md §3). */
data class RelayMessage(val from: String, val fromPk: String, val body: String)

/** Talks to the relay: registration over HTTPS, messages over one WebSocket. */
class L2RelayClient(
    private val http: OkHttpClient = OkHttpClient.Builder()
        .pingInterval(PING_SECONDS, TimeUnit.SECONDS)
        .build(),
) {
    private var socket: WebSocket? = null

    /** `https://relay.example/` with path stripped; http only for localhost. */
    fun baseUrl(input: String): String {
        val uri = URI(input.trim())
        val local = uri.host == "localhost" || uri.host == "127.0.0.1"
        require(uri.scheme == "https" || (uri.scheme == "http" && local)) {
            "relay URL must use https"
        }
        val port = if (uri.port == -1) "" else ":${uri.port}"
        return "${uri.scheme}://${uri.host}$port/"
    }

    /** Registers this phone; returns (device id, token). Blocking: call off the main thread. */
    fun register(relayUrl: String, publicKeyB64: String, pushToken: String?): Pair<String, String> {
        val body = buildJsonObject {
            put("publicKey", publicKeyB64)
            put("kind", "phone")
            pushToken?.let { put("pushToken", it) }
        }.toString().toRequestBody("application/json".toMediaType())
        val request = Request.Builder().url("${baseUrl(relayUrl)}v1/devices").post(body).build()
        http.newCall(request).execute().use { response ->
            check(response.code == HTTP_CREATED) { "relay registration failed: ${response.code}" }
            val o = Json.parseToJsonElement(response.body.string()) as JsonObject
            return o.text("id") to o.text("token")
        }
    }

    /** Tells the relay this phone's FCM token. Blocking: call off the main thread. */
    fun setPushToken(relayUrl: String, token: String, pushToken: String) {
        val body = buildJsonObject { put("pushToken", pushToken) }
            .toString()
            .toRequestBody("application/json".toMediaType())
        val request = Request.Builder()
            .url("${baseUrl(relayUrl)}v1/devices/me")
            .header("Authorization", "Bearer $token")
            .put(body)
            .build()
        http.newCall(request).execute().use { check(it.isSuccessful) { "relay: ${it.code}" } }
    }

    /**
     * Opens the WebSocket and authenticates. [onMessage] gets every delivered frame;
     * [onState] gets `true` once the relay says ready and `false` when the socket closes.
     */
    fun connect(
        relayUrl: String,
        token: String,
        onMessage: (RelayMessage) -> Unit,
        onState: (Boolean) -> Unit,
    ) {
        disconnect()
        val wsUrl = baseUrl(relayUrl).replaceFirst("http", "ws") + "v1/ws"
        socket = http.newWebSocket(
            Request.Builder().url(wsUrl).build(),
            object : WebSocketListener() {
                override fun onOpen(webSocket: WebSocket, response: Response) {
                    webSocket.send(buildJsonObject { put("t", "auth"); put("token", token) }.toString())
                }

                override fun onMessage(webSocket: WebSocket, text: String) {
                    val o = runCatching { Json.parseToJsonElement(text) as JsonObject }.getOrNull()
                        ?: return
                    when (o.textOrNull("t")) {
                        "ready" -> onState(true)
                        "msg" -> {
                            val from = o.textOrNull("from")
                            val fromPk = o.textOrNull("fromPk")
                            val body = o.textOrNull("body")
                            if (from != null && fromPk != null && body != null) {
                                onMessage(RelayMessage(from, fromPk, body))
                            }
                        }
                    }
                }

                override fun onClosed(webSocket: WebSocket, code: Int, reason: String) =
                    onState(false)

                override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) =
                    onState(false)
            },
        )
    }

    /** Sends an already sealed body to device [to]. False if not connected. */
    fun send(to: String, body: String): Boolean =
        socket?.send(
            buildJsonObject {
                put("t", "send")
                put("to", to)
                put("body", body)
            }.toString(),
        ) == true

    /** Closes the WebSocket, if open. */
    fun disconnect() {
        socket?.close(1000, null)
        socket = null
    }

    private fun JsonObject.textOrNull(k: String) =
        (get(k) as? JsonPrimitive)?.takeIf { it.isString }?.content

    private fun JsonObject.text(k: String) = textOrNull(k) ?: error("relay response lacks $k")
}
