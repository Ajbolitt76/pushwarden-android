package com.x8bit.bitwarden.data.vault.l2.pc

import com.bitwarden.core.data.manager.dispatcher.DispatcherManager
import com.bitwarden.data.manager.appstate.AppStateManager
import com.bitwarden.data.manager.appstate.model.AppForegroundState
import com.bitwarden.vault.CipherView
import com.x8bit.bitwarden.data.auth.repository.AuthRepository
import com.x8bit.bitwarden.data.vault.l2.L2Crypto
import com.x8bit.bitwarden.data.vault.l2.L2Field
import com.x8bit.bitwarden.data.vault.l2.L2Hosts
import com.x8bit.bitwarden.data.vault.l2.L2Manager
import com.x8bit.bitwarden.data.vault.l2.b64
import com.x8bit.bitwarden.data.vault.l2.isL2Value
import com.x8bit.bitwarden.data.vault.l2.unb64
import com.x8bit.bitwarden.data.vault.manager.model.GetCipherResult
import com.x8bit.bitwarden.data.vault.repository.VaultRepository
import com.x8bit.bitwarden.data.vault.repository.model.GenerateTotpResult
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.net.URI
import java.time.Clock
import java.time.Duration
import java.time.Instant

private val REQUEST_MAX_AGE: Duration = Duration.ofSeconds(60)
private val REPLAY_WINDOW: Duration = Duration.ofMinutes(10)
private val PAIRING_TIMEOUT: Duration = Duration.ofSeconds(120)
private const val MAX_PENDING_PER_PC = 3
private const val RECONNECT_DELAY_MS = 5_000L
private const val CONNECT_TIMEOUT_MS = 15_000L

/** How long a fill request may wait for the user (PROTOCOL.md §6). */
val PC_FILL_REQUEST_LIFETIME: Duration = REQUEST_MAX_AGE
/** X25519 public keys and pairing nonces are both 32 bytes. */
private const val KEY_BYTES = 32

/** A fill request from a paired PC, waiting for the user. */
data class PcFillRequest(
    val requestId: String,
    val pcId: String,
    val pcName: String,
    val itemId: String,
    val itemName: String,
    val username: String?,
    val origin: String,
    val host: String,
    val requestTime: Instant,
)

/** Pairing progress shown on the PC autofill screen (PROTOCOL.md §5). */
sealed class PcPairing {
    /** Waiting for a `pairRequest`/`pairReveal` from the extension. */
    data object Waiting : PcPairing()

    /** Both screens should now show [phrase]; the user confirms or rejects. */
    data class Confirm(val pcName: String, val phrase: String) : PcPairing()
}

/** Everything the PC autofill screen shows. */
data class PcAutofillState(
    val relayUrl: String? = null,
    val phoneId: String? = null,
    val connected: Boolean = false,
    val pcs: List<PairedPc> = emptyList(),
    val pairing: PcPairing? = null,
    val requests: List<PcFillRequest> = emptyList(),
)

/**
 * Phone side of PC autofill: relay registration, pairing, and approving fill requests
 * (DESIGN.md flows 3–4, PROTOCOL.md §5–6). The relay connection is open whenever the app is in
 * the foreground with the vault unlocked, so requests reach the approval dialog at once; in the
 * background the relay queues them and wakes the phone with FCM.
 */
interface L2PcAutofillManager {
    /** Current state for the active user. */
    val stateFlow: StateFlow<PcAutofillState>

    /** Registers this phone with the relay at [relayUrl]. */
    suspend fun register(relayUrl: String): Result<Unit>

    /**
     * Pairs with the PC whose QR code was scanned (PROTOCOL.md §5b): registers with its relay
     * if needed, stores the PC and sends the proof. Call after the user confirmed.
     */
    suspend fun pairWithQr(qr: L2QrPair, phoneName: String): Result<Unit>

    /** Opens the relay connection and reloads state. */
    fun connect()

    /** Closes the relay connection and drops pairing and pending requests. */
    fun disconnect()

    /** Starts accepting a `pairRequest` (only while this is on). */
    fun startPairing()

    /** Ends pairing; [accept] stores the PC and tells it, otherwise rejects it. */
    fun finishPairing(accept: Boolean)

    /** Sends the password (and TOTP code) for [requestId]. Call after user verification. */
    fun approve(requestId: String)

    /** Denies [requestId]. */
    fun deny(requestId: String)

    /** Forgets the PC [pcId] and tells it. */
    fun unpair(pcId: String)

    /** A new FCM token: remembered, and sent to the relay if this phone is registered. */
    fun onPushToken(token: String)
}

/** Default [L2PcAutofillManager]. */
@Suppress("TooManyFunctions", "LongParameterList")
class L2PcAutofillManagerImpl(
    private val crypto: L2Crypto,
    private val store: L2PcStore,
    private val relay: L2RelayClient,
    private val l2Manager: L2Manager,
    private val vaultRepository: VaultRepository,
    private val authRepository: AuthRepository,
    private val clock: Clock,
    private val wordlist: () -> List<String>,
    private val dispatcherManager: DispatcherManager,
    appStateManager: AppStateManager,
) : L2PcAutofillManager {
    private val scope = CoroutineScope(dispatcherManager.io)
    private val mutex = Mutex()
    private val mutableState = MutableStateFlow(PcAutofillState())
    override val stateFlow: StateFlow<PcAutofillState> = mutableState.asStateFlow()

    private var pairingMode = false
    private var session: PairingSession? = null
    private var pairingTimeout: Job? = null
    private val seenRequestIds = mutableMapOf<String, Instant>()

    private class PairingSession(
        val extId: String,
        val extPk: String,
        val name: String,
        val commit: ByteArray,
        val nPhone: ByteArray,
        var nExt: ByteArray? = null,
        var phrase: String? = null,
    )

    private val userId: String? get() = authRepository.activeUserId

    /** Foreground with the vault unlocked: the only time requests can be shown and answered. */
    @Volatile
    private var wanted = false
    private var reconnect: Job? = null

    init {
        combine(
            appStateManager.appForegroundStateFlow,
            authRepository.userStateFlow,
        ) { fg, user ->
            fg == AppForegroundState.FOREGROUNDED && user?.activeAccount?.isVaultUnlocked == true
        }
            .distinctUntilChanged()
            .onEach { open ->
                wanted = open
                if (open) connect() else disconnect()
            }
            .launchIn(scope)
    }

    override suspend fun register(relayUrl: String): Result<Unit> =
        withContext(dispatcherManager.io) {
            runCatching {
                val user = checkNotNull(userId)
                val base = relay.baseUrl(relayUrl)
                val (pk, sk) = crypto.boxKeyPair()
                val (id, token) = relay.register(base, b64(pk), store.pushToken)
                // A new identity: earlier pairings were with the old key and are dropped.
                store.save(user, PcAutofillConfig(base, id, token, b64(pk), b64(sk)))
                connect()
            }
        }

    override fun connect() {
        val config = userId?.let(store::load)
        mutableState.update {
            PcAutofillState(relayUrl = config?.relayUrl, phoneId = config?.deviceId, pcs = config?.pcs.orEmpty())
        }
        config ?: return
        reconnect?.cancel()
        relay.connect(
            relayUrl = config.relayUrl,
            token = config.token,
            onMessage = { m -> scope.launch { mutex.withLock { onRelayMessage(m) } } },
            onState = { connected ->
                mutableState.update { it.copy(connected = connected) }
                // Dropped while it should be open (network change, relay restart): retry.
                if (!connected && wanted) {
                    reconnect?.cancel()
                    reconnect = scope.launch {
                        delay(RECONNECT_DELAY_MS)
                        if (wanted && !mutableState.value.connected) connect()
                    }
                }
            },
        )
    }

    override suspend fun pairWithQr(qr: L2QrPair, phoneName: String): Result<Unit> =
        withContext(dispatcherManager.io) {
            runCatching {
                val user = checkNotNull(userId)
                val base = relay.baseUrl(qr.relayUrl)
                if (store.load(user)?.relayUrl != base) register(base).getOrThrow()
                if (!mutableState.value.connected) connect()
                // Messages sent before the relay's "ready" would arrive before auth.
                withTimeout(CONNECT_TIMEOUT_MS) { mutableState.first { it.connected } }
                mutex.withLock {
                    val config = checkNotNull(store.load(user))
                    val extPk = b64(qr.extPublicKey)
                    val pcs = config.pcs.filterNot { it.id == qr.extId } +
                        PairedPc(id = qr.extId, publicKey = extPk, name = qr.pcName)
                    store.save(user, config.copy(pcs = pcs))
                    mutableState.update { it.copy(pcs = pcs) }
                    val proof = crypto.qrProof(qr.secret, unb64(config.publicKey), qr.extPublicKey)
                    send(config, qr.extId, extPk, L2PcReplies.qrPair(b64(proof), phoneName))
                }
            }
        }

    override fun disconnect() {
        relay.disconnect()
        pairingMode = false
        session = null
        pairingTimeout?.cancel()
        mutableState.update { it.copy(connected = false, pairing = null, requests = emptyList()) }
    }

    override fun startPairing() {
        pairingMode = true
        session = null
        mutableState.update { it.copy(pairing = PcPairing.Waiting) }
        pairingTimeout?.cancel()
        pairingTimeout = scope.launch {
            delay(PAIRING_TIMEOUT.toMillis())
            mutex.withLock { endPairing() }
        }
    }

    override fun finishPairing(accept: Boolean) {
        scope.launch {
            mutex.withLock {
                val s = session
                val user = userId
                val config = user?.let(store::load)
                if (s?.phrase != null && config != null) {
                    if (accept) {
                        val pcs = config.pcs.filterNot { it.id == s.extId } +
                            PairedPc(id = s.extId, publicKey = s.extPk, name = s.name)
                        store.save(user, config.copy(pcs = pcs))
                        mutableState.update { it.copy(pcs = pcs) }
                    }
                    val nExt = s.nExt?.let(::b64)
                    val reply = if (accept && nExt != null) {
                        L2PcReplies.pairAccept(nExt)
                    } else {
                        L2PcReplies.pairReject(nExt)
                    }
                    send(config, s.extId, s.extPk, reply)
                }
                endPairing()
            }
        }
    }

    override fun approve(requestId: String) {
        scope.launch { mutex.withLock { answer(requestId, approve = true) } }
    }

    override fun deny(requestId: String) {
        scope.launch { mutex.withLock { answer(requestId, approve = false) } }
    }

    override fun unpair(pcId: String) {
        scope.launch {
            mutex.withLock {
                val user = userId ?: return@withLock
                val config = store.load(user) ?: return@withLock
                val pc = config.pcs.find { it.id == pcId } ?: return@withLock
                send(config, pc.id, pc.publicKey, L2PcReplies.unpair())
                val pcs = config.pcs - pc
                store.save(user, config.copy(pcs = pcs))
                mutableState.update { st ->
                    st.copy(pcs = pcs, requests = st.requests.filterNot { it.pcId == pcId })
                }
            }
        }
    }

    override fun onPushToken(token: String) {
        store.pushToken = token
        scope.launch {
            val config = userId?.let(store::load) ?: return@launch
            // Best effort: on failure the relay can't wake the phone until the next token.
            runCatching { relay.setPushToken(config.relayUrl, config.token, token) }
        }
    }

    private suspend fun onRelayMessage(m: RelayMessage) {
        val user = userId ?: return
        val config = store.load(user) ?: return
        val text = runCatching {
            crypto.open(m.body, unb64(m.fromPk, KEY_BYTES), unb64(config.secretKey))
        }.getOrNull() ?: return
        val msg = runCatching { L2PcMessage.parse(text) }.getOrNull() ?: return
        val pc = config.pcs.find { it.id == m.from && it.publicKey == m.fromPk }
        when (msg) {
            is L2PcMessage.PairRequest -> onPairRequest(config, m, msg)
            is L2PcMessage.PairReveal -> onPairReveal(config, m, msg)
            is L2PcMessage.FillRequest -> pc?.let { onFillRequest(config, it, msg) }
            L2PcMessage.Unpair -> pc?.let { removePc(user, config, it) }
        }
    }

    private fun onPairRequest(config: PcAutofillConfig, m: RelayMessage, msg: L2PcMessage.PairRequest) {
        // Only while the pairing screen is open, and one attempt at a time (PROTOCOL.md §5).
        if (!pairingMode || session != null) return
        val s = PairingSession(m.from, m.fromPk, msg.name, msg.commit, crypto.random(KEY_BYTES))
        session = s
        send(config, s.extId, s.extPk, L2PcReplies.pairChallenge(b64(s.nPhone)))
    }

    private fun onPairReveal(config: PcAutofillConfig, m: RelayMessage, msg: L2PcMessage.PairReveal) {
        val s = session ?: return
        if (m.from != s.extId || m.fromPk != s.extPk || s.phrase != null) return
        val extPk = unb64(s.extPk, KEY_BYTES)
        if (!crypto.checkCommitment(s.commit, extPk, msg.nonce)) {
            send(config, s.extId, s.extPk, L2PcReplies.pairReject(null))
            endPairing()
            return
        }
        s.nExt = msg.nonce
        val phrase = crypto.fingerprintPhrase(
            phonePk = unb64(config.publicKey, KEY_BYTES),
            extPk = extPk,
            nExt = msg.nonce,
            nPhone = s.nPhone,
            wordlist = wordlist(),
        )
        s.phrase = phrase
        mutableState.update { it.copy(pairing = PcPairing.Confirm(s.name, phrase)) }
    }

    private suspend fun onFillRequest(
        config: PcAutofillConfig,
        pc: PairedPc,
        msg: L2PcMessage.FillRequest,
    ) {
        val now = clock.instant()
        seenRequestIds.entries.removeIf { Duration.between(it.value, now) > REPLAY_WINDOW }
        val reject = { send(config, pc.id, pc.publicKey, L2PcReplies.fillResult(msg.requestId, "rejected")) }
        val age = Duration.between(Instant.ofEpochMilli(msg.time), now).abs()
        val pending = mutableState.value.requests.count { it.pcId == pc.id }
        if (age > REQUEST_MAX_AGE || msg.requestId in seenRequestIds || pending >= MAX_PENDING_PER_PC) {
            reject()
            return
        }
        seenRequestIds[msg.requestId] = now
        val cipher = rawCipher(msg.itemId)
        val plain = cipher?.login?.password
            ?.takeIf { it.isL2Value() }
            ?.let { l2Manager.decryptField(msg.itemId, it, L2Field.PASSWORD).getOrNull() }
        // Only the hosts sealed in the ciphertext count; L1 URIs could be attacker-edited.
        if (cipher == null || plain == null || !L2Hosts.originAllowed(msg.origin, plain.hosts)) {
            reject()
            return
        }
        val request = PcFillRequest(
            requestId = msg.requestId,
            pcId = pc.id,
            pcName = pc.name,
            itemId = msg.itemId,
            itemName = cipher.name,
            // The sealed username: the L1 one could have been renamed on a compromised PC.
            username = plain.username,
            origin = msg.origin,
            host = URI(msg.origin).host,
            requestTime = Instant.ofEpochMilli(msg.time),
        )
        mutableState.update { it.copy(requests = it.requests + request) }
    }

    private suspend fun answer(requestId: String, approve: Boolean) {
        val user = userId ?: return
        val config = store.load(user) ?: return
        val request = mutableState.value.requests.find { it.requestId == requestId } ?: return
        mutableState.update { st -> st.copy(requests = st.requests - request) }
        val pc = config.pcs.find { it.id == request.pcId } ?: return
        val now = clock.instant()
        val reply = when {
            Duration.between(request.requestTime, now) > REQUEST_MAX_AGE -> {
                L2PcReplies.fillResult(requestId, "expired")
            }

            !approve -> L2PcReplies.fillResult(requestId, "denied")
            else -> approvedReply(request, now)
        }
        send(config, pc.id, pc.publicKey, reply)
    }

    private suspend fun approvedReply(request: PcFillRequest, now: Instant): String {
        val cipher = rawCipher(request.itemId)
        val login = cipher?.login
        val plain = login?.password
            ?.takeIf { it.isL2Value() }
            ?.let { l2Manager.decryptField(request.itemId, it, L2Field.PASSWORD).getOrNull() }
        if (cipher == null || plain == null || !L2Hosts.originAllowed(request.origin, plain.hosts)) {
            return L2PcReplies.fillResult(request.requestId, "error")
        }
        val isPremium = authRepository.userStateFlow.value?.activeAccount?.isPremium == true
        val totp = login.totp?.takeIf { isPremium || cipher.organizationUseTotp }?.let { seed ->
            if (seed.isL2Value()) {
                // The TOTP value passes its own item, field and host checks (PROTOCOL.md §6).
                l2Manager.decryptField(request.itemId, seed, L2Field.TOTP).getOrNull()
                    ?.takeIf { L2Hosts.originAllowed(request.origin, it.hosts) }
                    ?.let { L2Totp.code(it.secret, now) }
            } else {
                (vaultRepository.generateTotp(request.itemId, now) as? GenerateTotpResult.Success)?.code
            }
        }
        return L2PcReplies.fillResult(request.requestId, "approved", plain.secret, totp)
    }

    /** The cipher as stored, L2 ciphertext intact. */
    private suspend fun rawCipher(itemId: String): CipherView? =
        (vaultRepository.getCipher(itemId) as? GetCipherResult.Success)?.cipherView
            ?.takeIf { it.deletedDate == null }

    private fun removePc(user: String, config: PcAutofillConfig, pc: PairedPc) {
        val pcs = config.pcs - pc
        store.save(user, config.copy(pcs = pcs))
        mutableState.update { st -> st.copy(pcs = pcs, requests = st.requests.filterNot { it.pcId == pc.id }) }
    }

    private fun endPairing() {
        pairingMode = false
        session = null
        pairingTimeout?.cancel()
        mutableState.update { it.copy(pairing = null) }
    }

    private fun send(config: PcAutofillConfig, to: String, toPk: String, json: String) {
        relay.send(to, crypto.seal(json, unb64(toPk, KEY_BYTES), unb64(config.secretKey)))
    }
}
