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

<!-- wp:image {"id":6899,"sizeSlug":"large"} -->
<figure class="wp-block-image size-large"><img src="https://www.codyhosterman.com/wp-content/uploads/2020/09/image-15-1024x495.png" alt="" class="wp-image-6899"/></figure>
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
<h2>Latest version 1.2.0.2 (September 1st, 2020)</h2>
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

<!-- wp:list -->
<ul><li>New-PureOneCertificate</li><li>Get-PureOnePublicKey</li><li>New-PureOneJwt</li><li>New-PureOneConnection </li><li>Get-PureOneArrays </li><li>New-PureOneOperation </li><li>Get-PureOneArrayTags </li><li>Set-PureOneArrayTags </li><li>Remove-PureOneArrayTags </li><li>Get-PureOneArrayNetworking </li><li>Get-PureOneMetricDetails </li><li>Get-PureOneMetrics </li><li>Get-PureOneVolumes </li><li>Get-PureOnePods </li><li>Get-PureOneVolumeSnapshots </li><li>Get-PureOneFileSystems </li><li>Get-PureOneFileSystemSnapshots </li><li>Get-PureOneArrayBusyMeter</li></ul>
<!-- /wp:list -->

<!-- wp:paragraph -->
<p><br><br></p>
<!-- /wp:paragraph -->
