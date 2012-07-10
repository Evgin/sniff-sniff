import sys
import logging

__author__ = 'e.goncharov'


def main():
    logging.basicConfig(level=logging.WARNING, filename='root.log', )
    logging.warning('Watch out!') # will print a message to the console
    logging.info('I told you so') # will not print anything


if __name__ == '__main__':
    sys.exit(main())