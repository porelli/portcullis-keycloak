<#-- The person's notice at their next sign-in (contract §8.1 "The notice", D45):
     one line per unseen impersonation (ImpersonationNotice.line), or the generic
     text when impersonation.json can't be read; Continue posts to the required
     action. Every value relies on FreeMarker's HTML auto-escaping, never unescaped. -->
<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
    <#if section = "header">
        ${msg("portcullisImpersonationNoticeTitle")}
    <#elseif section = "form">
        <div id="portcullis-impersonation-notice" data-generic="${portcullisNotice.generic?c}">
            <#if portcullisNotice.generic>
                <p>${msg("portcullisImpersonationNoticeGeneric")}</p>
            <#else>
                <ul class="portcullis-notice-lines">
                    <#list portcullisNotice.lines as line>
                        <li class="portcullis-notice-line">${line}</li>
                    </#list>
                </ul>
            </#if>
            <form id="portcullis-notice-form" action="${url.loginAction}" method="post">
                <input id="portcullis-notice-continue" class="${(properties.kcButtonPrimaryClass)!""}" type="submit" value="${msg("portcullisImpersonationNoticeContinue")}"/>
            </form>
        </div>
    </#if>
</@layout.registrationLayout>
