/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.provisioning;

import java.util.Locale;

import org.junit.Test;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.assertj.core.api.Assertions.*;

/**
 * @author Rob Winch
 * @since 5.1
 */
public class InMemoryUserDetailsManagerTests {
	private final UserDetails user = PasswordEncodedUser.user();

	private InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager(this.user);

	@Test
	public void changePassword() {
		String newPassword = "newPassword";
		this.manager.updatePassword(this.user, newPassword);
		assertThat(this.manager.loadUserByUsername(this.user.getUsername()).getPassword()).isEqualTo(newPassword);
	}

	@Test
	public void changePasswordWhenUsernameIsNotInLowercase() {
		UserDetails userNotLowerCase = User.withUserDetails(PasswordEncodedUser.user())
				.username("User")
				.build();

		String newPassword = "newPassword";
		this.manager.updatePassword(userNotLowerCase, newPassword);
		assertThat(this.manager.loadUserByUsername(userNotLowerCase.getUsername()).getPassword()).isEqualTo(newPassword);
	}

	@Test
	public void loadUserByUsernameWhenTurkishLocaleThenUsernameIsNotLocaleDependent() {
		Locale defaultLocale = Locale.getDefault();
		try {
			Locale.setDefault(Locale.forLanguageTag("tr-TR"));
			UserDetails admin = User.withUserDetails(PasswordEncodedUser.admin())
					.username("ADMIN")
					.build();
			InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager(admin);

			assertThat(manager.userExists("admin")).isTrue();
			assertThat(manager.loadUserByUsername("admin").getUsername()).isEqualTo("ADMIN");
			// dotless i (U+0131) must not resolve to the "ADMIN" user
			assertThat(manager.userExists("adm\u0131n")).isFalse();
			assertThatThrownBy(() -> manager.loadUserByUsername("adm\u0131n"))
					.isInstanceOf(UsernameNotFoundException.class);
		}
		finally {
			Locale.setDefault(defaultLocale);
		}
	}

	@Test
	public void updatePasswordWhenTurkishLocaleThenUpdatesSameUser() {
		Locale defaultLocale = Locale.getDefault();
		try {
			Locale.setDefault(Locale.forLanguageTag("tr-TR"));
			UserDetails admin = User.withUserDetails(PasswordEncodedUser.admin())
					.username("admin")
					.build();
			InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager(admin);
			UserDetails upperCaseAdmin = User.withUserDetails(admin)
					.username("ADMIN")
					.build();

			manager.updatePassword(upperCaseAdmin, "newPassword");

			assertThat(manager.loadUserByUsername("admin").getPassword()).isEqualTo("newPassword");
		}
		finally {
			Locale.setDefault(defaultLocale);
		}
	}
}
