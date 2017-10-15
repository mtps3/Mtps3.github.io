---
title: CVE
permalink: "/cve/"
layout: page
---

<span class="discreet">Sort by <a href="/tags">tag</a>, <a href="/authors">author</a></span>

{% for post in site.categories.cve %}
   {% capture this_year %}{{ post.date | date: "%Y" }}{% endcapture %}

   {% if forloop.first %}
<h3>{{this_year}}</h3>
<ul>
   {% else %}
      {% if this_year != prev_year %}
</ul>
<h3>{{this_year}}</h3>
<ul>
      {% endif %}
   {% endif %}

<li><!--{{ post.date | date: "%b %-d, %Y" }} --> <a href="{{ post.url | prepend: site.baseurl }}">{{ post.title }}</a></li>

   {% capture prev_year %}{{ post.date | date: "%Y" }}{% endcapture %}

   {% if forloop.last %}
</ul>
   {% endif %}
{% endfor %}


subscribe [via Atom]({{ "/feed.xml" | prepend: site.baseurl }})
