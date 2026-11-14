<#-- The CONFIGURE_TOTP override's refusal (contract §8.1 "Authenticator-app
     codes"): the message and a link back to the Sign-in page. Nothing was
     generated or stored. Every value relies on FreeMarker's HTML
     auto-escaping, never unescaped. -->
<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
    <#if section = "header">
        ${msg("portcullisTotpRefusedTitle")}
    <#elseif section = "form">
        <div id="portcullis-totp-refused">
            <p>${msg(portcullis.message)}</p>
            <p><a id="portcullis-sign-in-methods" class="${(properties.kcButtonDefaultClass)!""}" href="${portcullis.signinUrl}">${msg("portcullisSignInMethods")}</a></p>
        </div>
    </#if>
</@layout.registrationLayout>
