package com.x8bit.bitwarden.data.vault.l2.pc

import com.x8bit.bitwarden.data.vault.l2.L2FormatException
import com.x8bit.bitwarden.data.vault.l2.unb64
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put

private const val NONCE_BYTES = 32
private const val REQUEST_ID_BYTES = 16
private const val NAME_MAX = 64
private const val ITEM_ID_MAX = 64
private const val ORIGIN_MAX = 2048
private const val QR_NAME_MAX = 64

/** The end-to-end messages the phone handles (PROTOCOL.md §4), parsed and validated. */
sealed class L2PcMessage {
    /** Extension asks to pair. */
    data class PairRequest(val name: String, val commit: ByteArray) : L2PcMessage()

    /** Extension reveals its pairing nonce. */
    data class PairReveal(val nonce: ByteArray) : L2PcMessage()

    /** Extension asks to fill an item. */
    data class FillRequest(
        val requestId: String,
        val itemId: String,
        val origin: String,
        val time: Long,
    ) : L2PcMessage()

    /** Either side ends the pairing. */
    data object Unpair : L2PcMessage()

    companion object {
        /** Parses [text]; `null` for types the phone ignores. Throws on malformed input. */
        fun parse(text: String): L2PcMessage? {
            val o = try {
                Json.parseToJsonElement(text) as? JsonObject
            } catch (e: IllegalArgumentException) {
                throw L2FormatException("bad JSON: ${e.javaClass.simpleName}")
            } ?: throw L2FormatException("not an object")
            if (o.prim("v")?.int != 1) throw L2FormatException("unsupported message version")
            return when (o.str("type")) {
                "pairRequest" -> PairRequest(
                    name = o.str("name", NAME_MAX),
                    commit = unb64(o.str("commit"), NONCE_BYTES),
                )

                "pairReveal" -> PairReveal(unb64(o.str("nonce"), NONCE_BYTES))
                "fillRequest" -> FillRequest(
                    requestId = o.str("requestId").also { unb64(it, REQUEST_ID_BYTES) },
                    itemId = o.str("itemId", ITEM_ID_MAX),
                    origin = o.str("origin", ORIGIN_MAX),
                    time = o.prim("time")?.long ?: throw L2FormatException("bad time"),
                )

                "unpair" -> Unpair
                else -> null
            }
        }

        private fun JsonObject.prim(k: String): JsonPrimitive? =
            (get(k) as? JsonPrimitive)?.takeUnless { it.contentOrNull == null }

        private fun JsonObject.str(k: String, max: Int = Int.MAX_VALUE): String {
            val p = get(k) as? JsonPrimitive
            if (p == null || !p.isString || p.content.length > max) throw L2FormatException("bad $k")
            return p.content
        }
    }
}

/** JSON for the messages the phone sends (PROTOCOL.md §4). */
object L2PcReplies {
    /** `pairChallenge`. */
    fun pairChallenge(nonceB64: String): String = msg("pairChallenge") { put("nonce", nonceB64) }

    /** `pairAccept`, echoing this attempt's `nExt` so it can't be replayed later. */
    fun pairAccept(nExtB64: String): String = msg("pairAccept") { put("nonce", nExtB64) }

    /** `pairReject`, echoing `nExt` when it is known. */
    fun pairReject(nExtB64: String?): String = msg("pairReject") {
        nExtB64?.let { put("nonce", it) }
    }

    /** `unpair`. */
    fun unpair(): String = msg("unpair") {}

    /** `qrPair`: proves this phone scanned the PC's QR code (PROTOCOL.md §5b). */
    fun qrPair(proofB64: String, name: String): String = msg("qrPair") {
        put("proof", proofB64)
        put("name", name.take(QR_NAME_MAX))
    }

    /** `fillResult`; secrets only with `approved`. */
    fun fillResult(
        requestId: String,
        status: String,
        password: String? = null,
        totp: String? = null,
    ): String = msg("fillResult") {
        put("requestId", requestId)
        put("status", status)
        if (status == "approved") {
            password?.let { put("password", it) }
            totp?.let { put("totp", it) }
        }
    }

    private fun msg(
        type: String,
        body: kotlinx.serialization.json.JsonObjectBuilder.() -> Unit,
    ): String = buildJsonObject {
        put("v", 1)
        put("type", type)
        body()
    }.toString()
}
