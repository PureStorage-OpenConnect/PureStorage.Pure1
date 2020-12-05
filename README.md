# PureStorage.Pure1
 Pure Storage Pure1 Module
<!-- wp:paragraph -->
<p>To help our customers I have written a module that makes it easy to connect to the Pure1 REST API with PowerShell.</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>The module is called&nbsp;<a href="https://www.powershellgallery.com/packages/PureStorage.Pure1">PureStorage.Pure1</a></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><em>To report issues or request new features, please enter them here:</em></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><a href="https://github.com/PureStorage-OpenConnect/PureStorage.Pure1/issues">https://github.com/PureStorage-OpenConnect/PureStorage.Pure1/issues</a></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>For questions, <a href="https://codeinvite.purestorage.com/">join our Pure Storage Code Slack</a> team!</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>There are a couple of places you can download this. The best option is the&nbsp;<a href="https://www.powershellgallery.com/packages/PureStorage.Pure1">PowerShell gallery</a>! This allows you to use&nbsp;<a href="https://docs.microsoft.com/en-us/powershell/module/powershellget/install-module?view=powershell-6">install-module</a>&nbsp;to automatically install the module. </p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>To install:</p>
<!-- /wp:paragraph -->

<!-- wp:preformatted -->
<pre class="wp-block-preformatted">install-module PureStorage.Pure1</pre>
<!-- /wp:preformatted -->

<!-- wp:paragraph -->
<p>To load the module:</p>
<!-- /wp:paragraph -->

<!-- wp:preformatted -->
<pre class="wp-block-preformatted">import-module PureStorage.Pure1 </pre>
<!-- /wp:preformatted -->

<!-- wp:paragraph -->
<p>To update:</p>
<!-- /wp:paragraph -->

<!-- wp:preformatted -->
<pre class="wp-block-preformatted">update-module PureStorage.Pure1</pre>
<!-- /wp:preformatted -->

<!-- wp:paragraph -->
<p>Blog post on Pure1 REST Authentication:</p>
<!-- /wp:paragraph -->

<!-- wp:core-embed/wordpress {"url":"https://www.codyhosterman.com/2019/12/pure1-rest-api-authentication-made-easy/","type":"wp-embed","providerNameSlug":"cody-hosterman","className":""} -->
<figure class="wp-block-embed-wordpress wp-block-embed is-type-wp-embed is-provider-cody-hosterman"><div class="wp-block-embed__wrapper">
https://www.codyhosterman.com/2019/12/pure1-rest-api-authentication-made-easy/
</div></figure>
<!-- /wp:core-embed/wordpress -->

<!-- wp:paragraph -->
<p>For Linux or MacOS authentication:</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><a href="https://www.codyhosterman.com/2020/09/pure1-powershell-module-core-support-and-more/" data-type="post" data-id="6867">Pure1 PowerShell Module Core Support (and more!)</a></p>
<!-- /wp:paragraph -->

<!-- wp:core-embed/wordpress {"url":"https://www.codyhosterman.com/2020/11/improved-certificate-management-for-pure1-powershell-module/","type":"wp-embed","providerNameSlug":"cody-hosterman","className":""} -->
<figure class="wp-block-embed-wordpress wp-block-embed is-type-wp-embed is-provider-cody-hosterman"><div class="wp-block-embed__wrapper">
https://www.codyhosterman.com/2020/11/improved-certificate-management-for-pure1-powershell-module/
</div></figure>
<!-- /wp:core-embed/wordpress -->

<!-- wp:paragraph -->
<p>Use either get-help or get-command to see the details:</p>
<!-- /wp:paragraph -->

<!-- wp:image {"id":7229,"sizeSlug":"large"} -->
<figure class="wp-block-image size-large"><img src="https://www.codyhosterman.com/wp-content/uploads/2020/11/image-47-1024x557.png" alt="" class="wp-image-7229"/></figure>
<!-- /wp:image -->

<!-- wp:image {"id":6900,"sizeSlug":"large"} -->
<figure class="wp-block-image size-large"><img src="https://www.codyhosterman.com/wp-content/uploads/2020/09/image-16-980x1024.png" alt="" class="wp-image-6900"/></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p><strong>Comment on Versioning</strong></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Versions numbering w.x.y.z (for example 1.2.0.0)</p>
<!-- /wp:paragraph -->

<!-- wp:list -->
<ul><li>W is iterated for large updates</li><li>X is iterated for new cmdlets/significant enhancements</li><li>Y is iterated for new functions to existing cmdlets</li><li>Z is iterated for bug fixes</li></ul>
<!-- /wp:list -->

<!-- wp:heading -->
<h2>Latest version 1.4.2.0 (December 5th, 2020)</h2>
<!-- /wp:heading -->

<!-- wp:paragraph -->
<p>See version details: <a href="https://github.com/PureStorage-OpenConnect/PureStorage.Pure1/projects/7" target="_blank" rel="noreferrer noopener">https://github.com/PureStorage-OpenConnect/PureStorage.Pure1/projects/6</a></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><strong>New features:</strong></p>
<!-- /wp:paragraph -->

<!-- wp:list -->
<ul><li><a rel="noreferrer noopener" href="https://github.com/PureStorage-OpenConnect/PureStorage.Pure1/issues/41" target="_blank">Allow cmdlets to use default cert/key without specifying them.</a></li><li><a rel="noreferrer noopener" href="https://github.com/PureStorage-OpenConnect/PureStorage.Pure1/issues/39" target="_blank">Allow JWT to be sent to PureOneConnection directly requiring no cert/or key to be local to the script.</a></li><li><a rel="noreferrer noopener" href="https://github.com/PureStorage-OpenConnect/PureStorage.Pure1/issues/40" target="_blank">Allow for a certificate to be exported on a Windows system for backup or sharing.</a></li></ul>
<!-- /wp:list -->

<!-- wp:paragraph -->
<p><strong>Bug Fixes:</strong></p>
<!-- /wp:paragraph -->

<!-- wp:list -->
<ul><li><a rel="noreferrer noopener" href="https://github.com/PureStorage-OpenConnect/PureStorage.Pure1/issues/35" target="_blank">Get-PureOneVolume did not filter properly on volume name</a></li><li><a href="https://github.com/PureStorage-OpenConnect/PureStorage.Pure1/issues/38" target="_blank" rel="noreferrer noopener">New-PureOneConnection did not work on PowerShell 5.x</a></li></ul>
<!-- /wp:list -->

<!-- wp:heading -->
<h2>Version 1.4.1.1 (November 25th, 2020)</h2>
<!-- /wp:heading -->

<!-- wp:paragraph -->
<p>See version details: https://github.com/PureStorage-OpenConnect/PureStorage.Pure1/projects/6</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><strong>New features:</strong></p>
<!-- /wp:paragraph -->

<!-- wp:list -->
<ul><li>Default Certificate Designation</li><li><a href="https://github.com/PureStorage-OpenConnect/PureStorage.Pure1/issues/36" target="_blank" rel="noreferrer noopener">Get-PureOneCertificate</a></li><li><a href="https://github.com/PureStorage-OpenConnect/PureStorage.Pure1/issues/37" target="_blank" rel="noreferrer noopener">Set-PureOneDefaultCertificate</a></li><li>Auto-detection of default certificates</li></ul>
<!-- /wp:list -->

<!-- wp:paragraph -->
<p><strong>Bug Fixes:</strong></p>
<!-- /wp:paragraph -->

<!-- wp:list -->
<ul><li>Improved error handling of authentication</li><li><a href="https://github.com/PureStorage-OpenConnect/PureStorage.Pure1/issues/34" target="_blank" rel="noreferrer noopener">Multiple certificates passed into JWT command causing bad JWTs</a></li></ul>
<!-- /wp:list -->

<!-- wp:heading -->
<h2>Version 1.3.0.0 (September 24th, 2020)</h2>
<!-- /wp:heading -->

<!-- wp:paragraph -->
<p>See  version details: <a href="https://github.com/PureStorage-OpenConnect/PureStorage.Pure1/projects/3">https://github.com/PureStorage-OpenConnect/PureStorage.Pure1/projects/3</a></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><strong>New features:</strong></p>
<!-- /wp:paragraph -->

<!-- wp:list -->
<ul><li><a href="https://github.com/PureStorage-OpenConnect/PureStorage.Pure1/issues/32">Auto-discovery of default private key on Unix platforms. </a></li><li>New cmdlet: <a href="https://github.com/PureStorage-OpenConnect/PureStorage.Pure1/issues/28">pull all array alerts Get-PureOneAlert</a></li><li>New cmdlet: <a href="https://github.com/PureStorage-OpenConnect/PureStorage.Pure1/issues/31">pull all support contracts Get-PureOneSupportContract</a></li></ul>
<!-- /wp:list -->

<!-- wp:paragraph -->
<p><strong>Bug Fixes:</strong></p>
<!-- /wp:paragraph -->

<!-- wp:list -->
<ul><li><a href="https://github.com/PureStorage-OpenConnect/PureStorage.Pure1/issues/30">Issue where new-pureoneconnection was not terminating upon first error</a></li></ul>
<!-- /wp:list -->

<!-- wp:paragraph -->
<p><br><br></p>
<!-- /wp:paragraph -->
