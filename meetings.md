---
layout: page
title: Meetings
permalink: /meetings/
---

<ul>
{% for post in site.categories.meeting %}
<li>{{ post.when }} <a href="{{ post.url | prepend: site.baseurl }}">{{ post.title }}</a></li>
{% endfor %}
</ul>


subscribe [via Atom]({{ "/feed.xml" | prepend: site.baseurl }})
