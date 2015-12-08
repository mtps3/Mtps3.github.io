---
layout: page
title: Writeups
permalink: /writeups/
---

<ul>
{% for post in site.categories.writeup %}
<li><!--{{ post.date | date: "%b %-d, %Y" }} --> <a href="{{ post.url | prepend: site.baseurl }}">{{ post.title }}</a></li>
{% endfor %}
</ul>


subscribe [via Atom]({{ "/feed.xml" | prepend: site.baseurl }})
