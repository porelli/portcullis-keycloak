<#-- portcullis-template's page (contract §8.1 "Native-OIDC apps"): the copy of
     mockup signin-people.html section 2, which group-gate's needs-stronger
     page matches. Every value relies on FreeMarker's HTML auto-escaping
     (Keycloak renders .ftl with the HTML output format), never unescaped.
     In an impersonated session the attribute impersonation (the banner,
     D43) is set and shown first. -->
<#import "template.ftl" as layout>
<#-- "a <b>password</b> and a <b>security key</b>": bold only the method words where asked. -->
<#macro methods list bold=false><#list list as m>${msg("portcullisArticle_" + m)} <#if bold><b>${msg("portcullisMethod_" + m)}</b><#else>${msg("portcullisMethod_" + m)}</#if><#sep> ${msg("portcullisAnd")} </#sep></#list></#macro>
<@layout.registrationLayout displayMessage=false; section>
    <#if section = "header">
        ${msg("portcullisNeedsStrongerTitle", portcullis.app)}
    <#elseif section = "form">
        <div id="needs-stronger">
            <#if impersonation??>
                <p id="portcullis-impersonation-banner" class="portcullis-banner">
                    ${msg("portcullisImpersonationBanner", impersonation.person, impersonation.admin, impersonation.reason, impersonation.minutesLeft?c)}
                    <#if impersonation.stopUrl??><a id="portcullis-impersonation-stop-banner" class="${(properties.kcButtonDefaultClass)!""}" href="${impersonation.stopUrl}">${msg("portcullisImpersonationStop")}</a></#if>
                </p>
            </#if>
            <p>
                <#if portcullis.signedIn?has_content>
                    ${msg("portcullisNeedsStrongerSignedIn")} <@methods list=portcullis.signedIn bold=true/>.
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
                <#if portcullis.setUpPasskey><a id="portcullis-set-up-passkey" class="${(properties.kcButtonPrimaryClass)!""}" href="${portcullis.signinUrl}">${msg("portcullisSetUpPasskey")}</a></#if>
                <#if portcullis.setUpSecurityKey><a id="portcullis-set-up-security-key" class="${(properties.kcButtonPrimaryClass)!""}" href="${portcullis.signinUrl}">${msg("portcullisSetUpSecurityKey")}</a></#if>
                <#if portcullis.setUpAuthenticator><a id="portcullis-set-up-authenticator" class="${(properties.kcButtonPrimaryClass)!""}" href="${portcullis.signinUrl}">${msg("portcullisSetUpAuthenticator")}</a></#if>
                <a id="portcullis-sign-in-methods" class="${(properties.kcButtonDefaultClass)!""}" href="${portcullis.signinUrl}">${msg("portcullisSignInMethods")}</a>
                <#if portcullis.askAdmin><span class="portcullis-sub">${msg("portcullisAskAdmin")}</span></#if>
            </p>
        </div>
    </#if>
</@layout.registrationLayout>
