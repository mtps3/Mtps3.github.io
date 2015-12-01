---
layout: page
title: Writeups
permalink: /writeups/
---

{% for post in site.posts %}
 * {{ post.date | date: "%b %-d, %Y" }} [{{ post.title }}]({{ post.url | prepend: site.baseurl }})
{% endfor %}


subscribe [via Atom]({{ "/feed.xml" | prepend: site.baseurl }})
