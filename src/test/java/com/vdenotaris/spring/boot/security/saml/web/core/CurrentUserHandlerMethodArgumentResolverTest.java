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
import com.vdenotaris.spring.boot.security.saml.web.stereotypes.CurrentUser;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.MethodParameter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.User;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.bind.support.WebArgumentResolver;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.ModelAndViewContainer;

import java.security.Principal;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes= TestConfig.class)
public class CurrentUserHandlerMethodArgumentResolverTest extends CommonTestSupport {

    @Autowired
    private CurrentUserHandlerMethodArgumentResolver resolver;

    private MethodParameter validParam;

    private MethodParameter notAnnotatedParam;

    private MethodParameter wrongTypeParam;

    @Before
    public void init() throws NoSuchMethodException {
        validParam = new MethodParameter(
        		MethodSamples.class.getMethod("validUser", User.class), 0);
        notAnnotatedParam = new MethodParameter(
        		MethodSamples.class.getMethod("notAnnotatedUser", User.class), 0);
        wrongTypeParam = new MethodParameter(
        		MethodSamples.class.getMethod("wrongTypeUser", Object.class), 0);
    }

    @Test
    public void testSupportsParameter() throws NoSuchMethodException {
        assertTrue(resolver.supportsParameter(validParam));
        assertFalse(resolver.supportsParameter(notAnnotatedParam));
        assertFalse(resolver.supportsParameter(wrongTypeParam));
    }

    @Test
    public void testResolveArgument() throws Exception {
        // given
        ModelAndViewContainer mavContainer = mock(ModelAndViewContainer.class);
        WebDataBinderFactory binderFactory = mock(WebDataBinderFactory.class);
        NativeWebRequest webRequest = mock(NativeWebRequest.class);
        User stubUser = new User(USER_NAME, "", Collections.emptyList());
        Principal stubPrincipal = new UsernamePasswordAuthenticationToken(stubUser, null);
        when(webRequest.getUserPrincipal()).thenReturn(stubPrincipal);

        // when/then
        assertEquals(stubUser,
                resolver.resolveArgument(validParam, mavContainer, webRequest,binderFactory));
        assertEquals(WebArgumentResolver.UNRESOLVED,
                resolver.resolveArgument(notAnnotatedParam, mavContainer, webRequest,binderFactory));
        assertEquals(WebArgumentResolver.UNRESOLVED,
                resolver.resolveArgument(wrongTypeParam, mavContainer, webRequest,binderFactory));
    }

    @SuppressWarnings("unused")
    private static final class MethodSamples {

        public void validUser(@CurrentUser User user) {}

        public void notAnnotatedUser(User user) {}

        public void wrongTypeUser(@CurrentUser Object user) {}
    }
}
