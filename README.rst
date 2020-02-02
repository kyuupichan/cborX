==================================
``cborX``: generic CBOR for Python
==================================

.. teaser-begin

``cborX`` is an efficient, robust and highly customisable CBOR implementation for Python.

It supports generic encoding and decoding, streaming of large or complex objects with low
resource consumption, and support for asynchronous operation is planned.

.. teaser-end

.. overview-begin

A familiar JSON-like ``dumps``, ``dump``, ``loads`` and ``load`` API is provided.

.. code-block:: pycon

   >>> import cborx

   >>> bin = dumps(Example)
   >>> bin.hex()
   Example result

   >>> loads(bin)
   19

.. overview-end


.. PI-begin


Project Information
===================

The code is released under the `MIT Licence <https://github.com/kyuupichan/cborx/LICENCE>`_.

The project is hosted on `GitHub <https://github.com/kyuupichan/cborx/>`_ with continuous
integration.

Please submit an issue on the `bug tracker <https://github.com/kyuupichan/cborx/issues>`_
if you have found a bug or have a suggestion.

Its documentation lives at `Read the Docs <https://cborx.readthedocs.io/>`_, and the
latest release on `PyPI <https://pypi.org/project/cbrox/>`_.  ``cborX`` is rigorously
tested on Python 3.6 and above.

.. PI-end
