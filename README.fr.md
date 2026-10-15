# LogHunter

**Outil blue team léger qui détecte les attaques dans les logs SSH et des serveurs web, et associe chaque alerte à une technique MITRE ATT&CK.**

*[English version](README.md)*

LogHunter lit les fichiers `auth.log` d'OpenSSH et les logs d'accès Apache/Nginx, les normalise en événements, applique des règles de détection sur des fenêtres temporelles glissantes, puis produit un rapport prêt pour le triage : dans le terminal, en JSON (pour un SIEM ou un script) ou en page HTML autonome.

![Rapport HTML LogHunter](docs/report.png)

## Ce qu'il détecte

| Règle | Signification | Sévérité | MITRE ATT&CK |
|---|---|---|---|
| `ssh_success_after_bruteforce` | Connexion réussie depuis une IP qui avait échoué de nombreuses fois. Le mot de passe a peut-être été deviné | Critique | T1078 |
| `ssh_bruteforce` | Trop d'échecs de connexion depuis une IP dans une fenêtre glissante | Élevée / Critique | T1110.001 |
| `ssh_password_spraying` | Une IP essaie de nombreux noms d'utilisateur différents | Élevée | T1110.003 |
| `web_sql_injection` | `UNION SELECT`, `' OR '1'='1`, `SLEEP()`, etc. Passe en critique si le serveur a répondu 2xx | Élevée / Critique | T1190 |
| `web_xss` | `<script>`, `onerror=`, `javascript:` dans l'URL | Élevée | T1190 |
| `web_path_traversal` | `../`, `/etc/passwd`, y compris en double encodage URL | Élevée / Critique | T1083 |
| `web_command_injection` | `; cat`, `| id`, `$(...)`, backticks | Élevée / Critique | T1059 |
| `web_sensitive_file_probe` | Requêtes vers `.env`, `.git/`, `wp-config.php`, sauvegardes | Moyenne | T1595.003 |
| `web_directory_scanning` | Rafale de réponses 4xx sur de nombreux chemins depuis une IP | Moyenne | T1595.003 |
| `web_scanner_user_agent` | Outils offensifs connus : sqlmap, Nikto, Nmap, gobuster, Nuclei... | Moyenne | T1595 |

## Démarrage rapide

```bash
git clone https://github.com/AlawiAhmedDev/loghunter.git
cd loghunter
pip install -e .            # aucune dépendance externe

loghunter analyze samples/auth.log samples/access.log --year 2026
```

### Sur un vrai serveur

```bash
sudo loghunter analyze /var/log/auth.log /var/log/nginx/access.log
sudo loghunter analyze /var/log/auth.log.*.gz          # logs compressés acceptés
loghunter analyze access.log -f html -o rapport.html   # rapport HTML
loghunter analyze access.log -f json -o alertes.json   # pour un SIEM ou jq
```

Les options (`--threshold`, `--window`, `--fail-on`, etc.) sont décrites dans le [README anglais](README.md#options) et avec `loghunter analyze --help`.

## Fonctionnement

- **Parsing** : chaque ligne est reconnue automatiquement (sshd au format syslog ou ISO-8601, Apache/Nginx au format combined). Les horodatages avec fuseau sont convertis en UTC. Les mois sont lus sans dépendre de la locale du système, donc l'outil fonctionne aussi sur un système en français ou en arabe. Les lignes inconnues ou mal formées sont comptées et ignorées.
- **Fenêtres glissantes** : la force brute et le scan utilisent une fenêtre glissante à deux pointeurs. 5 échecs en 2 minutes déclenchent une alerte, 5 échecs répartis sur une journée non.
- **Dédoublonnage** : sshd journalise `Invalid user X` et `Failed password for invalid user X` pour une seule tentative ; LogHunter ne la compte qu'une fois.
- **Décodage** : les URL sont décodées deux fois pour détecter l'évasion par double encodage (`%252e%252e%252f` → `../`).
- **Corrélation** : une réponse 2xx à une injection, ou une connexion réussie après une force brute, augmente la sévérité, car l'attaque a peut-être fonctionné.

## Tests

```bash
pip install -e ".[dev]"
pytest -v
```

27 tests vérifient chaque parser et chaque règle, les cas de faux positifs (un utilisateur qui se trompe une fois de mot de passe, des URL légitimes contenant *select* ou *union*) et une exécution complète sur les logs d'exemple. Ils tournent sur Python 3.10 à 3.13 via GitHub Actions.

## Données d'exemple

`samples/generate.py` génère les logs d'exemple à partir d'une graine fixe : trafic normal et cinq scénarios d'attaque (force brute suivie d'une connexion root réussie, password spraying lent, scan Nikto, injection SQL avec sqlmap, tentatives de path traversal et de XSS). Toutes les IP proviennent des plages de documentation RFC 5737.

## Pistes d'amélioration

- [ ] Enrichissement des IP (GeoIP, AbuseIPDB)
- [ ] Règles en YAML (style Sigma) au lieu de Python
- [ ] Mode surveillance (`tail -f`) pour l'alerte en temps réel
- [ ] Support des journaux d'événements Windows (4625 / 4624)
- [ ] Export vers Elasticsearch / Wazuh

## Avertissement

LogHunter est un outil d'apprentissage et de triage. Les règles à base de signatures ratent les attaques obfusquées et peuvent produire des faux positifs. Il ne remplace ni un SIEM ni un IDS. N'analysez que des logs auxquels vous avez le droit d'accéder.

## Auteur

**Alawi Masfar**, Master en Cybersécurité et Intelligence Artificielle
GitHub : [@AlawiAhmedDev](https://github.com/AlawiAhmedDev)

## Licence

[MIT](LICENSE)
