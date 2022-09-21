/**
* @name Subprocess Command injection or RCE
* @description User supplied input is not sanitized and could potentially cause
*              command injection or remote code execution vulnerabilities
* @kind problem
* @problem.severity critical
* @precision very-high
* @id python/subprocess-command-injection
* @tags security
*       logic
*/

import python
import semmle.python.security.dataflow.CommandInjectionCustomizations
import DataFlow::PathGraph

from Configuration config, DataFlow::PathNode source, DataFlow::Pathnode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "This command line depends on $@.", source.getNode(), "a user-provided value"
