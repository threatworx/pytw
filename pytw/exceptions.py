
class pytw_error(Exception):
	""" PYTW Errors """

	def __init__(self, msg):
		self.msg = msg

	def __repr__(self):
		return "<pytw_error: %s>" % self.msg

	def __str__(self):
		return str(self.msg)

