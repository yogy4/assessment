import os
import unittest
import coverage
from project.server import app, db, models
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand

COV = coverage.coverage(
    branch=True,
    include='project/*',
    omit=[
        'project/tests/*',
        'project/server/config.py',
        'project/server/*/__init__.py'
    ]
)

COV.start()

migrate = Migrate(app, db)
manager = Manager(app)
manager.add_command('db', MigrateCommand)

@manager.command
def test():
    """ menjalankan unit test tanpa coverage """
    tests = unittest.TestLoader().discover('project/tests', pattern='test*.py')
    result = unittest.TextTestRunner(verbosity=2).run(tests)
    if result.wasSuccesful():
        return 0
    return 1 

@manager.command
def cov():
    """Menjalankan unittest dengan coverage."""
    tests = unittest.TestLoader().discover('project/tests')
    result = unittest.TextTestRunner(verbosity=2).run(tests)
    if result.wasSuccessful():
        COV.stop()
        COV.save()
        print('Coverage Summary:')
        COV.report()
        basedir = os.path.abspath(os.path.dirname(__file__))
        covdir = os.path.join(basedir, 'tmp/coverage')
        COV.html_report(directory=covdir)
        print('HTML version: file://%s/index.html' % covdir)
        COV.erase()
        return 0
    return 1


@manager.command
def create_db():
    """Membuat table"""
    db.create_all()


@manager.command
def drop_db():
    """Menghapus table"""
    db.drop_all()


if __name__ == '__main__':
  manager.run()