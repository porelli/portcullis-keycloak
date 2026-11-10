<#-- portcullis-template's page (contract §8.1 "Native-OIDC apps"): the copy of
     mockup signin-people.html section 2, which group-gate's needs-stronger
     page matches. Every value relies on FreeMarker's HTML auto-escaping
     (Keycloak renders .ftl with the HTML output format), never unescaped. -->
<#import "template.ftl" as layout>
<#macro methods list><#list list as m>${msg("portcullisMethod_" + m)}<#sep> ${msg("portcullisAnd")} </#sep></#list></#macro>
<@layout.registrationLayout displayMessage=false; section>
    <#if section = "header">
        ${msg("portcullisNeedsStrongerTitle", portcullis.app)}
    <#elseif section = "form">
        <div id="needs-stronger">
            <p>
                <#if portcullis.signedIn?has_content>
                    ${msg("portcullisNeedsStrongerSignedIn")} <b><@methods list=portcullis.signedIn/></b>.
                <#else>
                    ${msg("portcullisNeedsStrongerSignedInNothing", portcullis.app)}
                </#if>
                ${msg("portcullisNeedsStrongerAccepts", portcullis.app)}
            </p>
            <ul>
                <#list portcullis.alternatives as alternative>
                    <li><@methods list=alternative.methods/><#if alternative.notSetUp> <span class="portcullis-sub">— ${msg("portcullisNeedsStrongerNotSetUp")}</span></#if></li>
                </#list>
            </ul>
            <p>
                <#if portcullis.setUpPasskey><a id="portcullis-set-up-passkey" class="${(properties.kcButtonPrimaryClass)!""}" href="${portcullis.accountUrl}">${msg("portcullisSetUpPasskey")}</a></#if>
                <#if portcullis.setUpSecurityKey><a id="portcullis-set-up-security-key" class="${(properties.kcButtonPrimaryClass)!""}" href="${portcullis.accountUrl}">${msg("portcullisSetUpSecurityKey")}</a></#if>
                <a id="portcullis-sign-in-methods" class="${(properties.kcButtonDefaultClass)!""}" href="${portcullis.accountUrl}">${msg("portcullisSignInMethods")}</a>
                <#if portcullis.askAdmin><span class="portcullis-sub">${msg("portcullisAskAdmin")}</span></#if>
            </p>
        </div>
    </#if>
</@layout.registrationLayout>
