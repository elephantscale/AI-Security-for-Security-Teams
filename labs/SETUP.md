## Setup Local Environment

Setup is done in each lab separately, but the steps are identical. Use the **Quick setup** script, or follow the manual steps below.

---

### Quick setup (recommended)

From inside the lab you want to run, execute the `setup.sh` script that lives in the `labs/` folder:

```sh
cd labs/01-Introduction      # or any lab directory
../setup.sh
```

This creates the virtual environment (`myenv`), registers the **My env** Jupyter kernel, installs that lab's `requirements.txt`, and ensures the shared `.env` exists at `labs/.env`.

When it finishes:

1. Add your API key to `labs/.env`:
   ```sh
   OPENAI_API_KEY=sk-...
   ```
2. Open the notebook and select the **My env** kernel (or run `source myenv/bin/activate` in your shell).

Repeat `../setup.sh` once per lab. Everything below is the same thing done by hand.

---

### Manual setup

1. **Navigate to the lab directory**
*  **IMPORTANT:** Setup is done in each lab separately, but the instruction are the same.

2. **Create a Virtual Environment**
   - Run the following command to create a virtual environment:
     ```sh
     python3 -m venv myenv
     ```

3. **Activate the Virtual Environment**
   - Activate the new virtual environment using:
     ```sh
     source myenv/bin/activate
     ```

4. **Install IPython Kernel**
    - Install `ipykernel` to attach the Jupyter environment to the same kernel:
      ```sh
      pip install ipykernel 
      ```

5. **Add Environment to Jupyter Kernel**
    - Add the current environment to the Jupyter kernel:
      ```sh
      python3 -m ipykernel install --user --name=myenv --display-name "My env"
      ```

6. **Install Lab Requirements**
   - Install the lab requirements specified in the `requirements.txt` file:
     ```sh
     pip install -r requirements.txt
     ```

7. **Create .env File for all API Keys**
    - We use one .env file at the root of all labs
   


