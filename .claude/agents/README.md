# Agents Claude Code

Ce dossier contient les agents (sous-agents) Claude Code de ce dépôt.
Ils sont disponibles dans toute session Claude Code ouverte sur ce dépôt,
depuis l'ordinateur comme depuis le téléphone (app Claude ou claude.ai/code).

## Créer un agent

Un agent = un fichier `.md` dans ce dossier, avec un en-tête YAML :

```markdown
---
name: nom-de-l-agent
description: Quand utiliser cet agent (Claude s'en sert pour décider de l'appeler).
tools: Read, Grep, Glob   # optionnel : sans cette ligne, l'agent a tous les outils
---

Instructions de l'agent (son rôle, sa méthode, le format de sa réponse).
```

## Agents disponibles

- `exemple-relecteur.md` : agent d'exemple qui relit un fichier ou un dossier
  et signale les erreurs. À copier pour créer les tiens.
