---
title: "Writeups"
layout: archive
permalink: /writeups/
author_profile: true
---

{% assign writeups = site.categories.writeup %}

{% for post in writeups %}
  {% include archive-single.html %}
{% endfor %}