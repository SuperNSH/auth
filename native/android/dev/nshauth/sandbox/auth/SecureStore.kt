package dev.nshauth.sandbox.auth

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * AES/GCM over AndroidKeyStore: one hardware-backed key seals every entry with
 * its own random IV, and only `{key -> iv, ciphertext}` reaches the app-private
 * JSON file. EncryptedSharedPreferences is deprecated; no plaintext token ever
 * touches disk here.
 */
internal class SecureStore(private val file: File) {

    private class Sealed(val iv: ByteArray, val ciphertext: ByteArray)

    fun save(key: String, value: String) {
        val entries = readEntries()
        entries[key] = seal(value)
        writeEntries(entries)
    }

    fun load(key: String): String? {
        val sealed = readEntries()[key] ?: return null
        return try {
            unseal(sealed)
        } catch (_: AEADBadTagException) {
            // Wrong tag: tampered ciphertext, or the Keymaster key was replaced
            // (device restore/wipe) and the data is unrecoverable. Drop the entry.
            dropEntry(key)
            null
        } catch (_: KeyPermanentlyInvalidatedException) {
            dropEntry(key)
            null
        }
        // Any other KeyStore error is transient: propagate it rather than wipe auth.
    }

    /** Deletes one entry, or the whole store when key is null. */
    fun clear(key: String?) {
        if (key == null) {
            file.delete()
            return
        }
        dropEntry(key)
    }

    /** Removes the entry when it exists, rewriting the store only then. */
    private fun dropEntry(key: String) {
        val entries = readEntries()
        if (entries.remove(key) != null) writeEntries(entries)
    }

    private fun readEntries(): MutableMap<String, Sealed> {
        if (!file.exists()) return LinkedHashMap()
        val obj = JSONObject(file.readText())
        val out = LinkedHashMap<String, Sealed>()
        for (name in obj.keys()) {
            val blob = obj.getJSONObject(name)
            out[name] = Sealed(
                Base64.decode(blob.getString("iv"), Base64.NO_WRAP),
                Base64.decode(blob.getString("ct"), Base64.NO_WRAP),
            )
        }
        return out
    }

    private fun writeEntries(entries: Map<String, Sealed>) {
        val obj = JSONObject()
        for ((name, sealed) in entries) {
            obj.put(name, JSONObject().put("iv", b64(sealed.iv)).put("ct", b64(sealed.ciphertext)))
        }
        file.parentFile?.mkdirs()
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeText(obj.toString())
        if (!tmp.renameTo(file)) {
            file.delete()
            check(tmp.renameTo(file)) { "cannot persist the secure store" }
        }
    }

    private fun seal(plaintext: String): Sealed {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        // The Keymaster key generates a fresh random IV for every seal.
        cipher.init(Cipher.ENCRYPT_MODE, key())
        return Sealed(cipher.iv, cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8)))
    }

    private fun unseal(sealed: Sealed): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(GCM_TAG_BITS, sealed.iv))
        return String(cipher.doFinal(sealed.ciphertext), Charsets.UTF_8)
    }

    private fun key(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val existing = try {
            keyStore.getKey(KEY_ALIAS, null)
        } catch (e: Exception) {
            null
        }
        if (existing is SecretKey) return existing
        // First use, or an entry the device reset left unrecoverable: recreate the key.
        try {
            keyStore.deleteEntry(KEY_ALIAS)
        } catch (e: Exception) {
            // the entry is already absent
        }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    private fun b64(bytes: ByteArray) = Base64.encodeToString(bytes, Base64.NO_WRAP)

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "nsh-auth-session"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_TAG_BITS = 128
    }
}
