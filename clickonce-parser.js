/*
 * Parser/inspector for ClickOnce deployments: the pair of XML manifests
 * (a "deployment manifest" -- a .application or .vsto file -- and the
 * "application manifest" it references -- a .manifest file), plus the
 * payload files they describe.
 *
 * Format background (see Microsoft's public ClickOnce manifest docs):
 *
 *   Deployment manifest (<name>.application):
 *     <asmv1:assembly> (root)
 *       <assemblyIdentity name="..." version="..." publicKeyToken="..." processorArchitecture="..." />
 *       <description asmv2:publisher="..." asmv2:product="..." />
 *       <deployment install="true|false" mapFileExtensions="true|false" minimumRequiredVersion="...">
 *         <subscription><update><beforeApplicationStartup/></update></subscription>
 *         <deploymentProvider codebase="https://.../app.application" />
 *       </deployment>
 *       <compatibleFrameworks>...</compatibleFrameworks>
 *       <dependency>
 *         <dependentAssembly dependencyType="install" codebase="App.manifest" size="1234">
 *           <assemblyIdentity name="App.exe" version="1.0.0.0" .../>
 *           <hash><dsig:DigestMethod Algorithm="..."/><dsig:DigestValue>...</dsig:DigestValue></hash>
 *         </dependentAssembly>
 *       </dependency>
 *
 *   Application manifest (<name>.exe.manifest):
 *     <asmv1:assembly>
 *       <assemblyIdentity name="App.exe" version="1.0.0.0" .../>
 *       <description asmv2:publisher="..." asmv2:product="..." />
 *       <trustInfo><security><applicationRequestMinimum>
 *         <PermissionSet Unrestricted="true"/>
 *         <defaultAssemblyRequest permissionSetReference="Custom"/>
 *       </applicationRequestMinimum>
 *       <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
 *       </security></trustInfo>
 *       <dependency><dependentAssembly dependencyType="install" codebase="App.exe" size="...">
 *         <assemblyIdentity name="App.exe" version="1.0.0.0" .../>
 *         <hash>...</hash>
 *       </dependentAssembly></dependency>
 *       <!-- one dependentAssembly per DLL/content file the app ships -->
 *       <file name="data.xml" size="512"/>
 *       <entryPoint>
 *         <assemblyIdentity name="App" version="1.0.0.0"/>
 *         <commandLine file="App.exe" parameters=""/>
 *       </entryPoint>
 *
 *   mapFileExtensions="true" on the deployment element means every payload
 *   file was published to the web server with a literal ".deploy" suffix
 *   appended to its real name (App.exe -> App.exe.deploy) so that plain
 *   web servers don't block executable-looking extensions. The suffix is
 *   ONLY a filename convention -- it changes nothing about the file's
 *   bytes -- so stripping it and re-hashing recovers the original file
 *   exactly, and the manifest's declared hash (computed by mage.exe/
 *   Visual Studio over the real, un-suffixed bytes) still matches the
 *   .deploy-suffixed file's content directly.
 *
 * This parser never executes anything from a ClickOnce package. It reads
 * the two manifests as XML, matches each declared dependentAssembly/file
 * entry against the files the user actually provided (by name, with or
 * without ".deploy"), and -- where a match exists -- recomputes the
 * declared digest algorithm over the real bytes via Web Crypto to report
 * whether the file's content still matches what the manifest says it
 * should be.
 *
 * A minimal hand-rolled XML reader is used (rather than DOMParser) so
 * this exact file runs unmodified in the Node ground-truth test suite
 * and in the browser. It handles exactly the well-formed subset that
 * real ClickOnce manifests use: nested elements, attributes (with or
 * without a namespace prefix -- prefixes are stripped since we only ever
 * look up local names), self-closing tags, and plain text content. It
 * does not attempt general XML (no DTDs, no CDATA sections, no entity
 * expansion beyond the five predefined XML entities).
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.ClickOnceParser = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  class ClickOnceParseError extends Error {}

  // ---------------------------------------------------------------------
  // Minimal XML reader
  // ---------------------------------------------------------------------

  const ENTITY_MAP = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };

  function decodeEntities(s) {
    return s.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (m, ent) => {
      if (ent[0] === '#') {
        const code = ent[1] === 'x' || ent[1] === 'X' ? parseInt(ent.slice(2), 16) : parseInt(ent.slice(1), 10);
        return Number.isFinite(code) ? String.fromCodePoint(code) : m;
      }
      return Object.prototype.hasOwnProperty.call(ENTITY_MAP, ent) ? ENTITY_MAP[ent] : m;
    });
  }

  function stripPrefix(name) {
    const i = name.indexOf(':');
    return i === -1 ? name : name.slice(i + 1);
  }

  // Parses `xmlText` into a tree of { tag, attrs: {localName: value},
  // children: [node...], text: string (concatenated direct text) }.
  function parseXml(xmlText) {
    let s = xmlText;
    // Strip a UTF-8 BOM if present, the XML declaration, comments, and
    // processing instructions -- none of them carry data we need.
    if (s.charCodeAt(0) === 0xfeff) s = s.slice(1);
    s = s.replace(/<\?[\s\S]*?\?>/g, '');
    s = s.replace(/<!--[\s\S]*?-->/g, '');
    s = s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, (m, inner) => inner.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c])));

    const tagRe = /<(\/?)([A-Za-z_][\w.\-:]*)((?:\s+[^<>"'=\s/][^<>"'=\s]*(?:\s*=\s*(?:"[^"]*"|'[^']*'))?)*)\s*(\/?)>|([^<]+)/g;
    const attrRe = /([^<>"'=\s/][^<>"'=\s]*)(?:\s*=\s*("([^"]*)"|'([^']*)'))?/g;

    const root = { tag: '#root', attrs: {}, children: [], text: '' };
    const stack = [root];
    let m;
    while ((m = tagRe.exec(s))) {
      if (m[5] !== undefined) {
        // Plain text between tags.
        const text = decodeEntities(m[5]);
        if (text.trim() !== '') stack[stack.length - 1].text += text;
        continue;
      }
      const closing = m[1] === '/';
      const rawTag = m[2];
      const attrsStr = m[3] || '';
      const selfClosing = m[4] === '/';
      const tag = stripPrefix(rawTag);

      if (closing) {
        if (stack.length <= 1) throw new ClickOnceParseError(`Unexpected closing tag </${rawTag}> with no matching open tag.`);
        const top = stack.pop();
        if (top.tag !== tag) {
          throw new ClickOnceParseError(`Mismatched XML tags: <${top.tag}> closed by </${rawTag}>.`);
        }
        continue;
      }

      const attrs = {};
      let am;
      attrRe.lastIndex = 0;
      while ((am = attrRe.exec(attrsStr))) {
        const name = stripPrefix(am[1]);
        const val = am[3] !== undefined ? am[3] : am[4] !== undefined ? am[4] : '';
        attrs[name] = decodeEntities(val);
      }

      const node = { tag, attrs, children: [], text: '' };
      stack[stack.length - 1].children.push(node);
      if (!selfClosing) stack.push(node);
    }
    if (stack.length !== 1) {
      throw new ClickOnceParseError(`XML has ${stack.length - 1} unclosed tag(s) -- the file may be truncated.`);
    }
    return root;
  }

  function findChild(node, tag) {
    return node.children.find((c) => c.tag === tag) || null;
  }
  function findChildren(node, tag) {
    return node.children.filter((c) => c.tag === tag);
  }
  function findDescendant(node, path) {
    let cur = node;
    for (const tag of path) {
      cur = findChild(cur, tag);
      if (!cur) return null;
    }
    return cur;
  }

  // ---------------------------------------------------------------------
  // Manifest-specific extraction
  // ---------------------------------------------------------------------

  function readAssemblyIdentity(node) {
    const idNode = node && findChild(node, 'assemblyIdentity');
    if (!idNode) return null;
    return {
      name: idNode.attrs.name || null,
      version: idNode.attrs.version || null,
      publicKeyToken: idNode.attrs.publicKeyToken || null,
      processorArchitecture: idNode.attrs.processorArchitecture || null,
      language: idNode.attrs.language || null,
    };
  }

  function readHash(node) {
    const hashNode = findChild(node, 'hash');
    if (!hashNode) return null;
    const methodNode = findChild(hashNode, 'DigestMethod');
    const valueNode = findChild(hashNode, 'DigestValue');
    return {
      algorithmUri: methodNode ? methodNode.attrs.Algorithm || null : null,
      digestValueBase64: valueNode ? valueNode.text.trim() : null,
    };
  }

  const DIGEST_URI_TO_SUBTLE = {
    'http://www.w3.org/2000/09/xmldsig#sha1': 'SHA-1',
    'http://www.w3.org/2001/04/xmlenc#sha256': 'SHA-256',
    'http://www.w3.org/2001/04/xmldsig-more#sha384': 'SHA-384',
    'http://www.w3.org/2001/04/xmlenc#sha512': 'SHA-512',
  };

  function readDependentAssemblies(assemblyNode) {
    const out = [];
    for (const depNode of findChildren(assemblyNode, 'dependency')) {
      for (const da of findChildren(depNode, 'dependentAssembly')) {
        out.push({
          dependencyType: da.attrs.dependencyType || null,
          codebase: da.attrs.codebase || null,
          size: da.attrs.size != null ? parseInt(da.attrs.size, 10) : null,
          identity: readAssemblyIdentity(da),
          hash: readHash(da),
        });
      }
    }
    return out;
  }

  function readFiles(assemblyNode) {
    return findChildren(assemblyNode, 'file').map((f) => ({
      name: f.attrs.name || null,
      size: f.attrs.size != null ? parseInt(f.attrs.size, 10) : null,
      group: f.attrs.group || null,
      optional: f.attrs.optional === 'true',
      hash: readHash(f),
    }));
  }

  function readDescription(assemblyNode) {
    const d = findChild(assemblyNode, 'description');
    if (!d) return {};
    return {
      publisher: d.attrs.publisher || null,
      product: d.attrs.product || null,
      iconFile: d.attrs.iconFile || null,
      suiteName: d.attrs.suiteName || null,
      supportUrl: d.attrs.supportUrl || null,
    };
  }

  // Parses a deployment manifest (.application/.vsto). Returns identity,
  // description, deployment settings, the deploymentProvider codebase,
  // and the single dependentAssembly that points at the application
  // manifest.
  function parseDeploymentManifest(xmlText) {
    const root = parseXml(xmlText);
    const assembly = findChild(root, 'assembly');
    if (!assembly) throw new ClickOnceParseError('No <assembly> root element found -- this does not look like a ClickOnce manifest.');
    const deployment = findChild(assembly, 'deployment');
    const deploymentProvider = deployment ? findChild(deployment, 'deploymentProvider') : null;
    const subscription = deployment ? findChild(deployment, 'subscription') : null;
    const update = subscription ? findChild(subscription, 'update') : null;

    return {
      kind: 'deployment',
      identity: readAssemblyIdentity(assembly),
      description: readDescription(assembly),
      install: deployment ? deployment.attrs.install === 'true' : null,
      mapFileExtensions: deployment ? deployment.attrs.mapFileExtensions === 'true' : false,
      minimumRequiredVersion: deployment ? deployment.attrs.minimumRequiredVersion || null : null,
      updatesBeforeStart: !!(update && findChild(update, 'beforeApplicationStartup')),
      deploymentProviderCodebase: deploymentProvider ? deploymentProvider.attrs.codebase || null : null,
      dependentAssemblies: readDependentAssemblies(assembly),
    };
  }

  // Parses an application manifest (<name>.exe.manifest). Returns
  // identity, description, trust/security summary, entry point, every
  // dependentAssembly (the exe itself + every dependent DLL), and every
  // loose <file> entry.
  function parseApplicationManifest(xmlText) {
    const root = parseXml(xmlText);
    const assembly = findChild(root, 'assembly');
    if (!assembly) throw new ClickOnceParseError('No <assembly> root element found -- this does not look like a ClickOnce manifest.');

    const trustInfo = findChild(assembly, 'trustInfo');
    const security = trustInfo ? findChild(trustInfo, 'security') : null;
    const requestMin = security ? findChild(security, 'applicationRequestMinimum') : null;
    const permissionSet = requestMin ? findChild(requestMin, 'PermissionSet') : null;
    const executionLevelNode = security ? findChild(security, 'requestedExecutionLevel') : null;
    const defaultAssemblyRequest = requestMin ? findChild(requestMin, 'defaultAssemblyRequest') : null;

    let trustLevel = 'unknown';
    if (permissionSet && permissionSet.attrs.Unrestricted === 'true') {
      trustLevel = 'Full Trust';
    } else if (defaultAssemblyRequest) {
      trustLevel = `Partial Trust (${defaultAssemblyRequest.attrs.permissionSetReference || 'custom'})`;
    } else if (permissionSet) {
      trustLevel = 'Partial Trust';
    }

    const entryPointNode = findChild(assembly, 'entryPoint');
    const commandLine = entryPointNode ? findChild(entryPointNode, 'commandLine') : null;

    return {
      kind: 'application',
      identity: readAssemblyIdentity(assembly),
      description: readDescription(assembly),
      trustLevel,
      requestedExecutionLevel: executionLevelNode ? executionLevelNode.attrs.level || null : null,
      entryPointFile: commandLine ? commandLine.attrs.file || null : null,
      entryPointParameters: commandLine ? commandLine.attrs.parameters || null : null,
      dependentAssemblies: readDependentAssemblies(assembly),
      files: readFiles(assembly),
    };
  }

  // ---------------------------------------------------------------------
  // Matching declared entries against uploaded files + hash verification
  // ---------------------------------------------------------------------

  // `uploadedFiles` is an array of {name, bytes: Uint8Array}. Matches by
  // exact name, or by name + ".deploy". Returns the match plus whether
  // the match required stripping ".deploy".
  function findUploadedFile(uploadedFiles, declaredName) {
    if (!declaredName) return null;
    const base = declaredName.split('/').pop().split('\\').pop();
    for (const f of uploadedFiles) {
      const fbase = f.name.split('/').pop().split('\\').pop();
      if (fbase === base) return { file: f, hadDeploySuffix: false };
      if (fbase === base + '.deploy') return { file: f, hadDeploySuffix: true };
    }
    return null;
  }

  async function digestBytes(subtleAlgo, bytes) {
    const digest = await crypto.subtle.digest(subtleAlgo, bytes);
    return base64FromBytes(new Uint8Array(digest));
  }

  function base64FromBytes(bytes) {
    if (typeof Buffer !== 'undefined') return Buffer.from(bytes).toString('base64');
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  // Builds one combined, verified file table entry for a declared
  // dependentAssembly or <file> entry.
  async function verifyEntry(declared, uploadedFiles) {
    const match = findUploadedFile(uploadedFiles, declared.codebase || declared.name);
    const row = {
      name: declared.codebase || declared.name,
      declaredSize: declared.size,
      declaredAlgorithmUri: declared.hash ? declared.hash.algorithmUri : null,
      declaredDigestBase64: declared.hash ? declared.hash.digestValueBase64 : null,
      uploaded: !!match,
      hadDeploySuffix: match ? match.hadDeploySuffix : false,
      actualSize: match ? match.file.bytes.length : null,
      status: 'missing',
    };
    if (!match) return row;
    if (!declared.hash || !declared.hash.digestValueBase64) {
      row.status = declared.size != null && declared.size === match.file.bytes.length ? 'present (no hash declared)' : 'present';
      return row;
    }
    const subtleAlgo = DIGEST_URI_TO_SUBTLE[declared.hash.algorithmUri];
    if (!subtleAlgo) {
      row.status = 'present (unsupported digest algorithm)';
      return row;
    }
    const actualDigest = await digestBytes(subtleAlgo, match.file.bytes);
    row.actualDigestBase64 = actualDigest;
    row.status = actualDigest === declared.hash.digestValueBase64 ? 'verified' : 'HASH MISMATCH';
    return row;
  }

  async function buildReport(deploymentXmlText, applicationXmlText, uploadedFiles) {
    const deployment = parseDeploymentManifest(deploymentXmlText);
    const rows = [];
    let application = null;
    let applicationMatch = null;

    if (deployment.dependentAssemblies.length) {
      const appManifestDecl = deployment.dependentAssemblies[0];
      rows.push(await verifyEntry(appManifestDecl, uploadedFiles));
      applicationMatch = findUploadedFile(uploadedFiles, appManifestDecl.codebase);
    }

    if (applicationXmlText) {
      application = parseApplicationManifest(applicationXmlText);
      for (const da of application.dependentAssemblies) {
        rows.push(await verifyEntry(da, uploadedFiles));
      }
      for (const f of application.files) {
        rows.push(await verifyEntry(f, uploadedFiles));
      }
    }

    return { deployment, application, rows };
  }

  return {
    ClickOnceParseError,
    parseXml,
    parseDeploymentManifest,
    parseApplicationManifest,
    findUploadedFile,
    verifyEntry,
    buildReport,
    DIGEST_URI_TO_SUBTLE,
  };
});
