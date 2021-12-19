/*
 * Copyright 2021 Vincenzo De Notaris
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

package com.vdenotaris.spring.boot.security.saml.web.controllers;

import com.vdenotaris.spring.boot.security.saml.web.CommonTestSupport;
import com.vdenotaris.spring.boot.security.saml.web.TestConfig;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.servlet.View;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = {TestConfig.class})
@WebAppConfiguration
public class SSOControllerTest extends CommonTestSupport {

    private static final Set<String> IDPS =
            Collections.unmodifiableSet(
            		new HashSet<>(Arrays.asList("idp1", "idp2", "idp3")));

    @InjectMocks
    SSOController ssoController;

    @Mock
    private MetadataManager metadata;

    @Mock
    private View mockView;

    private MockMvc mockMvc;

    @BeforeEach
    public void setUp()
    {
        mockMvc = standaloneSetup(ssoController).setSingleView(mockView).build();
    }

    @Test
    @WithMockUser
    public void testIdpSelectionWithUser() throws Exception {
        mockMvc.perform(get("/saml/discovery"))
                .andExpect(status().isOk())
                .andExpect(view().name("redirect:/landing"));
    }

    @Test
    public void testIdpSelection() throws Exception {
        // given
        when(metadata.getIDPEntityNames()).thenReturn(IDPS);

        // when / then
        mockMvc.perform(get("/saml/discovery").session(mockAnonymousHttpSession()))
                .andExpect(status().isOk())
                .andExpect(model().attribute("idps", IDPS))
                .andExpect(view().name("pages/discovery"));
    }

}
