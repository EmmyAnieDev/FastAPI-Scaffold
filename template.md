## 🧩 Template Customization Guide

After cloning this scaffold, update the following placeholders to personalize your new project:

### 📝 Change Project name to your App Name

```bash
mv ../FastAPI-Scaffold ../<your-app-name>
cd ../<your-app-name>
code .  # Open the project in your vs code editor
```

### 🗂️ Remove Git History

```bash
rm -rf .git
```

### 📄 `README.md`
- Replace all `---` placeholders with the actual project details:
  - Project name
  - Database information
  - Repository URL
  - Author or team info

### 🚀 `main.py`
- Add your **project name**:
  - Line `7`: Update the app title or project name
  - Line `8`: Update the app description
  - Line `25`: If applicable, update any references to the project name

### 📦 `pyproject.toml`
- Set your **project name**:
  - Line `2`: Replace `name = "---"` with your actual project name (use lowercase and hyphens)
- Add your **author information**:
  - Line `5`: Replace with your GitHub username and email, e.g.  
    `authors = ["your-username <your@email.com>"]`


### 🗑️ Delete Template

- Run the command below after completing the customization to keep your project clean.

```bash
rm template.md
```