/*
 * Copyright 2020 Vincenzo De Notaris
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.vdenotaris.spring.boot.security.saml.web;

import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

import java.util.Collections;
import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CommonTestSupport {

    public static final String USER_NAME = "UserName";

    public static final String USER_PASSWORD = "<abc123>";

    public static final String USER_ROLE = "ROLE_USER";

    public static final String ANONYMOUS_USER_KEY = "UserKey";

    public static final String ANONYMOUS_USER_PRINCIPAL = "UserPrincipal";

    public static final List<GrantedAuthority> AUTHORITIES =
            Collections.singletonList(new SimpleGrantedAuthority(USER_ROLE));

    public static final User USER_DETAILS = new User(USER_NAME, USER_PASSWORD, AUTHORITIES);

    public MockHttpSession mockHttpSession(boolean secured) {
        MockHttpSession mockSession = new MockHttpSession();

        SecurityContext mockSecurityContext = mock(SecurityContext.class);

        if (secured) {
            ExpiringUsernameAuthenticationToken principal =
                    new ExpiringUsernameAuthenticationToken(null, USER_DETAILS, USER_NAME, AUTHORITIES);
            principal.setDetails(USER_DETAILS);
            when(mockSecurityContext.getAuthentication()).thenReturn(principal);
        }

        SecurityContextHolder.setContext(mockSecurityContext);
        mockSession.setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                mockSecurityContext);

        return mockSession;
    }

    public MockHttpSession mockAnonymousHttpSession() {
        MockHttpSession mockSession = new MockHttpSession();

        SecurityContext mockSecurityContext = mock(SecurityContext.class);

        AnonymousAuthenticationToken principal =
                new AnonymousAuthenticationToken(
                        ANONYMOUS_USER_KEY,
                        ANONYMOUS_USER_PRINCIPAL,
                        AUTHORITIES);

        when(mockSecurityContext.getAuthentication()).thenReturn(principal);
        
        SecurityContextHolder.setContext(mockSecurityContext);
        mockSession.setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                mockSecurityContext);

        return mockSession;
    }
}
