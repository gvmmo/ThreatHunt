# 🕵️ ThreatHunt

> Plataforma OSINT para recopilación y análisis de información de fuentes abiertas.

![AWS](https://img.shields.io/badge/AWS-232F3E?style=flat-square&logo=amazonaws&logoColor=white)
![MongoDB](https://img.shields.io/badge/MongoDB-47A248?style=flat-square&logo=mongodb&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![Status](https://img.shields.io/badge/Status-En_desarrollo-yellow?style=flat-square)

---

## ¿Qué es ThreatHunt?

ThreatHunt es una aplicación web de ciberseguridad desarrollada en AWS, diseñada para la recopilación y análisis de información mediante técnicas OSINT. Permite realizar escaneos pasivos y activos configurables, integrando múltiples herramientas y APIs en una sola plataforma.

---

## ✨ Funcionalidades

- 🔍 **Escaneos pasivos y activos** configurables según las necesidades del usuario
- 🛠️ **Integración de herramientas**: Wappalyzer, Subfinder, WHOIS, VirusTotal y otras APIs externas
- 📄 **Resultados exportables** en archivos HTML descargables para revisión detallada
- 👤 **Sistema de autenticación** con registro y gestión de perfiles personalizados
- 🗄️ **Historial de escaneos** almacenado en MongoDB por usuario
- 🔑 **Gestión de API keys** personalizada para maximizar el potencial de cada herramienta

---

## 🔧 Stack Técnico

| Capa | Tecnología |
|------|-----------|
| Cloud | AWS |
| Base de datos | MongoDB |
| Herramientas OSINT | Subfinder, Wappalyzer, WHOIS, VirusTotal |
| Autenticación | Sistema propio con gestión de perfiles |
| Output | Reportes HTML exportables |

---

## 🚀 Instalación

```bash
# Clonar el repositorio
git clone https://github.com/gvmmo/threathunt.git
cd threathunt

# Instalar dependencias
pip install -r requirements.txt

# Configurar variables de entorno
cp .env.example .env
# Editar .env con tus API keys y configuración de MongoDB

# Ejecutar
python app.py
```

---

## ⚙️ Configuración de API Keys

ThreatHunt permite configurar claves personalizadas para las siguientes herramientas desde el panel de usuario:

- VirusTotal API
- Otras APIs externas compatibles

---

## 📌 Roadmap

- [x] Sistema de autenticación y perfiles
- [x] Escaneos pasivos y activos
- [x] Exportación de resultados en HTML
- [x] Historial de escaneos por usuario
- [ ] Nuevas herramientas OSINT integradas
- [ ] Mejoras en la visualización de resultados
- [ ] Notificaciones y alertas automáticas

---

## 👤 Autor

**gvmmo** — [LinkedIn](https://linkedin.com/in/ayman-dghoughi-nouri-a43204321) · [GitHub](https://github.com/gvmmo)
