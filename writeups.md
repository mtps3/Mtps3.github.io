---
layout: page
title: Writeups
permalink: /writeups/
---

{% for post in site.categories.writeup %}
 * {{ post.date | date: "%b %-d, %Y" }} [{{ post.title }}]({{ post.url | prepend: site.baseurl }})
{% endfor %}


subscribe [via Atom]({{ "/feed.xml" | prepend: site.baseurl }})
