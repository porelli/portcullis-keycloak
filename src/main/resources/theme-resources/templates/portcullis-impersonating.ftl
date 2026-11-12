<#-- The extension's impersonation page (contract §8.1 "Impersonation", D42, D43):
     mode refused (the start refused, or "Not while you are signed in as <person>"),
     ended ("Your session as <person> has ended.", with Sign in again and no Stop) or needs (an app's template the
     administrator's sign-in doesn't meet). Every mode shows the banner when the
     attribute impersonation is set, and Stop links to people.<domain>/impersonation/stop.
     Every value relies on FreeMarker's HTML auto-escaping, never unescaped. -->
<#import "template.ftl" as layout>
<#macro methods list><#list list as m>${msg("portcullisArticle_" + m)} ${msg("portcullisMethod_" + m)}<#sep> ${msg("portcullisOr")} </#sep></#list></#macro>
<@layout.registrationLayout displayMessage=false; section>
    <#if section = "header">
        <#if portcullis.mode = "ended">
            ${msg("portcullisImpersonationEndedTitle")}
        <#elseif portcullis.mode = "needs">
            ${msg("portcullisNeedsStrongerTitle", portcullis.app)}
        <#else>
            ${msg("portcullisImpersonationRefusedTitle")}
        </#if>
    <#elseif section = "form">
        <div id="impersonating" data-mode="${portcullis.mode}">
            <#if impersonation??>
                <p id="portcullis-impersonation-banner" class="portcullis-banner">
                    ${msg("portcullisImpersonationBanner", impersonation.person, impersonation.admin, impersonation.reason, impersonation.minutesLeft?c)}
                    <#if impersonation.stopUrl??><a id="portcullis-impersonation-stop-banner" class="${(properties.kcButtonDefaultClass)!""}" href="${impersonation.stopUrl}">${msg("portcullisImpersonationStop")}</a></#if>
                </p>
            </#if>
            <p>
                <#if portcullis.mode = "ended">
                    ${msg("portcullisImpersonationEnded", portcullis.person!"")}
                <#elseif portcullis.mode = "needs">
                    ${portcullis.app} ${msg("portcullisImpersonationNeeds")} <@methods list=portcullis.methods/>. ${msg("portcullisImpersonationNeedsWhy", portcullis.admin!"", portcullis.person!"")}
                <#elseif portcullis.start>
                    ${msg("portcullisImpersonationStartRefused")}
                <#else>
                    ${msg("portcullisImpersonationRefused", portcullis.person!"")}
                </#if>
            </p>
            <#if portcullis.signInAgainUrl??>
                <p><a id="portcullis-impersonation-sign-in-again" class="${(properties.kcButtonPrimaryClass)!""}" href="${portcullis.signInAgainUrl}">${msg("portcullisImpersonationSignInAgain")}</a></p>
            </#if>
            <#if portcullis.stopUrl??>
                <p><a id="portcullis-impersonation-stop" class="${(properties.kcButtonPrimaryClass)!""}" href="${portcullis.stopUrl}">${msg("portcullisImpersonationStop")}</a></p>
            </#if>
        </div>
    </#if>
</@layout.registrationLayout>
