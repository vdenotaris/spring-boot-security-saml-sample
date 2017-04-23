/*
 * Copyright 2017 Vincenzo De Notaris
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

package com.vdenotaris.spring.boot.security.saml.web.core;

import com.vdenotaris.spring.boot.security.saml.web.CommonTestSupport;
import com.vdenotaris.spring.boot.security.saml.web.TestConfig;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.saml2.core.NameID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes= TestConfig.class)
public class SAMLUserDetailsServiceImplTest extends CommonTestSupport {

    @Autowired
    private SAMLUserDetailsServiceImpl userDetailsService;

    @Test
    public void testLoadUserBySAML() {
        // given
        NameID mockNameID = mock(NameID.class);
        when(mockNameID.getValue()).thenReturn(USER_NAME);

        SAMLCredential credentialsMock = mock(SAMLCredential.class);
        when(credentialsMock.getNameID()).thenReturn(mockNameID);

        // when
        Object actual = userDetailsService.loadUserBySAML(credentialsMock);

        // / then
        assertNotNull(actual);
        assertTrue(actual instanceof User);

        User user = (User)actual;
        assertEquals(USER_NAME, user.getUsername());
        assertEquals(USER_PASSWORD, user.getPassword());
        assertTrue(user.isEnabled());
        assertTrue(user.isAccountNonExpired());
        assertTrue(user.isCredentialsNonExpired());
        assertTrue(user.isAccountNonLocked());
        assertEquals(1, user.getAuthorities().size());

        List<GrantedAuthority> authorities = new ArrayList<>(user.getAuthorities());
        Object authority = authorities.get(0);

        assertTrue(authority instanceof SimpleGrantedAuthority);
        assertEquals(USER_ROLE, ((SimpleGrantedAuthority)authority).getAuthority());
    }
}
