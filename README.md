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

<!-- wp:paragraph -->
<p>Use either get-help or get-command to see the details:</p>
<!-- /wp:paragraph -->

<!-- wp:image {"id":6982,"sizeSlug":"large"} -->
<figure class="wp-block-image size-large"><img src="https://www.codyhosterman.com/wp-content/uploads/2020/09/image-52-1024x528.png" alt="" class="wp-image-6982"/></figure>
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
<ul><li>W is iterated for large updates</li><li>X is iterated for new cmdlets</li><li>Y is iterated for new functions to existing cmdlets</li><li>Z is iterated for bug fixes</li></ul>
<!-- /wp:list -->

<!-- wp:heading -->
<h2>Latest version 1.3.0.1 (October 7th, 2020)</h2>
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
<ul><li><a href="https://github.com/PureStorage-OpenConnect/PureStorage.Pure1/issues/33">Issue where pipelining is broken for certificates with New-PureOneJwt</a></li></ul>
<!-- /wp:list -->

<!-- wp:heading -->
<h2>Previous version 1.2.0.3 (September 1st, 2020)</h2>
<!-- /wp:heading -->

<!-- wp:paragraph -->
<p>See  version details: <a href="https://github.com/PureStorage-OpenConnect/PureStorage.Pure1/projects/1">https://github.com/PureStorage-OpenConnect/PureStorage.Pure1/projects/1</a></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><strong>New features:</strong></p>
<!-- /wp:paragraph -->

<!-- wp:list -->
<ul><li>Core Support on Linux and MacOS</li><li>Multiple Pure1 Organizations</li></ul>
<!-- /wp:list -->

<!-- wp:paragraph -->
<p><strong>Bug Fixes:</strong></p>
<!-- /wp:paragraph -->

<!-- wp:list -->
<ul><li>Improved error handling</li><li><a href="https://github.com/PureStorage-OpenConnect/PureStorage.Pure1/issues/26" target="_blank" rel="noreferrer noopener">Fixed issue with New-PureOneOperation not terminating after failure (1.2.0.2)</a></li><li><a href="https://github.com/PureStorage-OpenConnect/PureStorage.Pure1/issues/25" target="_blank" rel="noreferrer noopener">Internal function to set REST header to JWT fails when not specifying token directly. (1.2.0.1)</a></li><li>Missing help examples</li></ul>
<!-- /wp:list -->

<!-- wp:paragraph -->
<p>Cmdlets:</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><br><br></p>
<!-- /wp:paragraph -->
