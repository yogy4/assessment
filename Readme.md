
# Untuk menjalankan project ini ada beberapa langkah yang harus dijalani

1. Lakukan Fork/Clone
2. Aktifkan virtualenv
3. Kemudian install requirements(pip install -r requirements.txt)

# Set Environment Variables(dalam contoh ini menggunakan os linux dan python 2.7)

bash
$ export APP_SETTINGS="project.server.config.DevelopmentConfig"

# bila ingin menjalankan dalam mode production

$ export APP_SETTINGS="project.server.config.ProductionConfig"

# kemudian set SECRET_KEY

$ export SECRET_KEY="blablabla"

# buat database

$ psql
 create database database_name

\q



# setelah itu lakukan migrasi

1. $ python manage.py create_db
2. $ python manage.py db init
3. $ python manage.py db migrate

# terakhir jalankan aplikasi

$ python manage.py runserver


# untuk pengujian

tanpa coverage:
$ python manage.py test


dengan coverage:
$ python manage.py cov
