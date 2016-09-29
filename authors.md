---
layout: page
title: Authors
hidden: true
---

<span class="discreet">Sort by <a href="/writeups">date</a>, <a href="/tags">tag</a></span>

{% assign post_list = site.categories.writeup %}
{% assign authors = (site.authors | sort:0) %}

{% for author in authors  %}
  {% assign id = author[0] %}
  {% assign info = author[1] %}
  <h3 id="{{ id }}-ref">Write-ups by {{ info.display_name | default: id }}</h3>
        {% if info %}
  <p>
            {% if info.web %}
  Personal Website: <a href="{{ info.web }}">{{ info.web }}</a><br />
            {% endif %}
            {% if info.twitter %}
  on <a href="https://twitter.com/{{ info.twitter }}">Twitter</a><br />
            {% endif %}
            {% if info.github %}
  on <a href="https://github.com/{{ info.github }}">Github</a><br />
            {% endif %}
  </p>
		{% endif %}
  <ul>
    {% for post in post_list %}
       {% if post.author contains id %}
         <li><a href="{{ post.url }}">{{ post.title }}</a></li>
       {% endif %}
    {% endfor %}
  </ul>
{% endfor %}
