package com.x8bit.bitwarden.data.vault.l2.di

import android.content.Context
import android.content.SharedPreferences
import com.bitwarden.data.datasource.disk.di.EncryptedPreferences
import com.x8bit.bitwarden.data.auth.repository.AuthRepository
import com.x8bit.bitwarden.data.vault.l2.pc.L2PcAutofillManager
import com.x8bit.bitwarden.data.vault.l2.pc.L2PcAutofillManagerImpl
import com.x8bit.bitwarden.data.vault.l2.pc.L2PcNotifier
import com.x8bit.bitwarden.data.vault.l2.pc.L2PcStore
import com.x8bit.bitwarden.data.vault.l2.pc.L2RelayClient
import dagger.hilt.android.qualifiers.ApplicationContext
import com.bitwarden.core.data.manager.dispatcher.DispatcherManager
import com.bitwarden.data.manager.appstate.AppStateManager
import com.bitwarden.data.datasource.disk.di.UnencryptedPreferences
import com.goterl.lazysodium.SodiumAndroid
import com.x8bit.bitwarden.data.auth.datasource.disk.AuthDiskSource
import com.x8bit.bitwarden.data.vault.l2.L2Crypto
import com.x8bit.bitwarden.data.vault.l2.L2KeyStore
import com.x8bit.bitwarden.data.vault.l2.L2KeyStoreImpl
import com.x8bit.bitwarden.data.vault.l2.L2Manager
import com.x8bit.bitwarden.data.vault.l2.L2ManagerImpl
import com.x8bit.bitwarden.data.vault.l2.L2SetupManager
import com.x8bit.bitwarden.data.vault.l2.L2SetupManagerImpl
import com.x8bit.bitwarden.data.vault.repository.VaultRepository
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import java.time.Clock
import javax.inject.Singleton

/**
 * Provides the L2 (second encryption level) dependencies.
 */
@Module
@InstallIn(SingletonComponent::class)
object L2Module {
    @Provides
    @Singleton
    fun provideL2Crypto(): L2Crypto = L2Crypto(SodiumAndroid())

    @Provides
    @Singleton
    fun provideL2KeyStore(
        @UnencryptedPreferences sharedPreferences: SharedPreferences,
    ): L2KeyStore = L2KeyStoreImpl(prefs = sharedPreferences)

    @Provides
    @Singleton
    fun provideL2Manager(
        crypto: L2Crypto,
        keyStore: L2KeyStore,
        authDiskSource: AuthDiskSource,
    ): L2Manager = L2ManagerImpl(
        crypto = crypto,
        keyStore = keyStore,
        authDiskSource = authDiskSource,
    )

    @Provides
    @Singleton
    fun provideL2SetupManager(
        crypto: L2Crypto,
        keyStore: L2KeyStore,
        l2Manager: L2Manager,
        vaultRepository: VaultRepository,
        authDiskSource: AuthDiskSource,
        clock: Clock,
        dispatcherManager: DispatcherManager,
    ): L2SetupManager = L2SetupManagerImpl(
        crypto = crypto,
        keyStore = keyStore,
        l2Manager = l2Manager,
        vaultRepository = vaultRepository,
        authDiskSource = authDiskSource,
        clock = clock,
        dispatcherManager = dispatcherManager,
    )

    @Provides
    @Singleton
    fun provideL2PcAutofillManager(
        @ApplicationContext context: Context,
        @EncryptedPreferences encryptedPreferences: SharedPreferences,
        crypto: L2Crypto,
        l2Manager: L2Manager,
        vaultRepository: VaultRepository,
        authRepository: AuthRepository,
        clock: Clock,
        dispatcherManager: DispatcherManager,
        appStateManager: AppStateManager,
    ): L2PcAutofillManager = L2PcAutofillManagerImpl(
        crypto = crypto,
        store = L2PcStore(prefs = encryptedPreferences),
        relay = L2RelayClient(),
        l2Manager = l2Manager,
        vaultRepository = vaultRepository,
        authRepository = authRepository,
        clock = clock,
        wordlist = {
            context.assets.open("l2/eff_large_wordlist.txt").bufferedReader().readLines()
        },
        dispatcherManager = dispatcherManager,
        appStateManager = appStateManager,
    )

    @Provides
    @Singleton
    fun provideL2PcNotifier(@ApplicationContext context: Context): L2PcNotifier =
        L2PcNotifier(context = context)
}
