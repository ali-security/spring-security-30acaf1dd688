/*
 * Copyright 2002-2026 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.crypto.encrypt;

import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;

import org.junit.Test;

import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;

/**
 * Tests for {@link AesGcmBytesEncryptor}.
 */
public class AesGcmBytesEncryptorTests {

	private final String secret = "value";

	private final String password = "password";

	private final String hexSalt = "deadbeef";

	@Test
	public void roundtripWhenUsingPasswordAndSaltThenEncryptsAndDecrypts() {
		CryptoAssumptions.assumeGCMJCE();
		AesGcmBytesEncryptor encryptor = AesGcmBytesEncryptor.withPassword(this.password,
				this.hexSalt).build();
		byte[] encrypted = encryptor.encrypt(this.secret.getBytes());
		assertThat(new String(encryptor.decrypt(encrypted))).isEqualTo(this.secret);
	}

	@Test
	public void roundtripWhenUsingSecretKeyThenEncryptsAndDecrypts() {
		CryptoAssumptions.assumeGCMJCE();
		PBEKeySpec keySpec = new PBEKeySpec(this.password.toCharArray(),
				Hex.decode(this.hexSalt), 1024, 256);
		SecretKey secretKey = CipherUtils.newSecretKey("PBKDF2WithHmacSHA1", keySpec);
		AesGcmBytesEncryptor encryptor = AesGcmBytesEncryptor.withSecretKey(secretKey)
				.build();
		byte[] encrypted = encryptor.encrypt(this.secret.getBytes());
		assertThat(new String(encryptor.decrypt(encrypted))).isEqualTo(this.secret);
	}

	@Test
	public void encryptWhenUsingFixedIvThenProducesKnownCiphertext() {
		CryptoAssumptions.assumeGCMJCE();
		BytesKeyGenerator fixedGenerator = fixedIvGenerator("4b0febebd439db7ca77153cb254520c3");
		AesGcmBytesEncryptor encryptor = AesGcmBytesEncryptor.withPassword(this.password,
				this.hexSalt).ivGenerator(fixedGenerator).build();
		byte[] encrypted = encryptor.encrypt(this.secret.getBytes());
		// Upstream pins 4b0f...e4d61ae3...7ed5ee here, but that value corresponds to a
		// PBKDF2WithHmacSHA1/1024 key, not the PBKDF2WithHmacSHA256/600000 derivation
		// withPassword performs; upstream CI never notices because its rewritten
		// CryptoAssumptions aborts these suites. Pinned instead to the correct value,
		// cross-checked against an independent PBKDF2/AES implementation.
		assertThat(new String(Hex.encode(encrypted))).isEqualTo(
				"4b0febebd439db7ca77153cb254520c332813cea271858a4fa3bb102d86b9c3317f1a94b8e");
		assertThat(new String(encryptor.decrypt(encrypted))).isEqualTo(this.secret);
	}

	@Test
	public void encryptProducesUniqueOutputAndIvIsPrepended() {
		CryptoAssumptions.assumeGCMJCE();
		AesGcmBytesEncryptor encryptor = AesGcmBytesEncryptor.withPassword(this.password,
				this.hexSalt).build();
		byte[] first = encryptor.encrypt(this.secret.getBytes());
		byte[] second = encryptor.encrypt(this.secret.getBytes());
		assertThat(Arrays.equals(first, second)).isFalse();
		assertThat(first.length).isGreaterThan(32);
	}

	@Test
	public void withSecretWhenAesBytesEncryptorEncryptsThenDecrypts() {
		CryptoAssumptions.assumeGCMJCE();
		PBEKeySpec keySpec = new PBEKeySpec(this.password.toCharArray(),
				Hex.decode(this.hexSalt), 1024, 256);
		SecretKey key = CipherUtils.newSecretKey("PBKDF2WithHmacSHA1", keySpec);
		AesBytesEncryptor deprecated = new AesBytesEncryptor(this.password, this.hexSalt,
				KeyGenerators.secureRandom(16), AesBytesEncryptor.CipherAlgorithm.GCM);
		AesGcmBytesEncryptor encryptor = AesGcmBytesEncryptor.withSecretKey(key).build();
		byte[] encrypted = deprecated.encrypt(this.secret.getBytes());
		assertThat(new String(encryptor.decrypt(encrypted))).isEqualTo(this.secret);
	}

	@Test
	public void aesBytesEncryptorWhenEncryptsThenAesGcmBytesEncryptorDecrypts() {
		CryptoAssumptions.assumeGCMJCE();
		PBEKeySpec keySpec = new PBEKeySpec(this.password.toCharArray(),
				Hex.decode(this.hexSalt), 1024, 256);
		SecretKey key = CipherUtils.newSecretKey("PBKDF2WithHmacSHA1", keySpec);
		AesGcmBytesEncryptor encryptor = AesGcmBytesEncryptor.withSecretKey(key)
				.ivGenerator(KeyGenerators.secureRandom(12)).build();
		AesBytesEncryptor deprecated = new AesBytesEncryptor(this.password, this.hexSalt,
				KeyGenerators.secureRandom(12), AesBytesEncryptor.CipherAlgorithm.GCM);
		byte[] encrypted = encryptor.encrypt(this.secret.getBytes());
		assertThat(new String(deprecated.decrypt(encrypted))).isEqualTo(this.secret);
	}

	@Test
	public void roundtripWhenUsingCustomIvGeneratorLengthThenEncryptsAndDecrypts() {
		CryptoAssumptions.assumeGCMJCE();
		AesGcmBytesEncryptor encryptor = AesGcmBytesEncryptor.withPassword(this.password,
				this.hexSalt).ivGenerator(KeyGenerators.secureRandom(12)).build();
		byte[] encrypted = encryptor.encrypt(this.secret.getBytes());
		assertThat(new String(encryptor.decrypt(encrypted))).isEqualTo(this.secret);
	}

	@Test
	public void withPasswordDerivesADifferentKeyThanAesBytesEncryptor() {
		CryptoAssumptions.assumeGCMJCE();
		AesBytesEncryptor deprecated = new AesBytesEncryptor(this.password, this.hexSalt,
				KeyGenerators.secureRandom(16), AesBytesEncryptor.CipherAlgorithm.GCM);
		AesGcmBytesEncryptor encryptor = AesGcmBytesEncryptor.withPassword(this.password,
				this.hexSalt).build();
		byte[] encrypted = deprecated.encrypt(this.secret.getBytes());
		try {
			encryptor.decrypt(encrypted);
			fail("Expected an IllegalStateException for a mismatched key");
		}
		catch (IllegalStateException expected) {
		}
	}

	@Test
	public void decryptDetectsAuthenticationTagTampering() {
		CryptoAssumptions.assumeGCMJCE();
		AesGcmBytesEncryptor encryptor = AesGcmBytesEncryptor.withPassword(this.password,
				this.hexSalt).build();
		byte[] encrypted = encryptor.encrypt(this.secret.getBytes());
		encrypted[17] ^= 0xFF;
		try {
			encryptor.decrypt(encrypted);
			fail("Expected an IllegalStateException for tampered ciphertext");
		}
		catch (IllegalStateException expected) {
		}
	}

	private static BytesKeyGenerator fixedIvGenerator(String hexIv) {
		final byte[] iv = Hex.decode(hexIv);
		return new BytesKeyGenerator() {

			public int getKeyLength() {
				return iv.length;
			}

			public byte[] generateKey() {
				return iv;
			}

		};
	}

}
