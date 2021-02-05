from distutils.core import setup

setup(name='Weblog Triage',
      version='1.0',
      description='A Python application for triaging web logs',
      author='Alejandro Prada',
      url='https://github.com/aleprada/weblog_triage',
      author_email='alejandro.prada86@gmail.com',
      packages=['weblog_triage.config', 'weblog_triage.core','weblog_triage.investigation'],
      package_data={'weblog_triage.config': ['weblog_triage.ini','attack_patterns.ini']},
      python_requires='>=3'
      )