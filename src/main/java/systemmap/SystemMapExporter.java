/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package systemmap;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;

import ghidra.app.util.*;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This is a Ghidra exporter plugin for the System.Map format. See
 * https://en.wikipedia.org/wiki/System.map for more details on the format.
 */
public class SystemMapExporter extends Exporter {

	/**
	 * Exporter constructor.
	 */
	public SystemMapExporter() {
		super("System Map", "map", null);
	}

	@Override
	public boolean supportsAddressRestrictedExport() {
		return false;
	}

	@Override
	public List<Option> getOptions(DomainObjectService domainObjectService) {
		return null;
	}

	@Override
	public void setOptions(List<Option> options) throws OptionException {
	}

	@Override
	public boolean export(File file, DomainObject domainObj, AddressSetView addrSet, TaskMonitor monitor)
			throws ExporterException, IOException {

		log.clear();

		if (!(domainObj instanceof Program)) {
			log.appendMsg("Unsupported type: " + domainObj.getClass().getName());
			return false;
		}

		Program program = (Program) domainObj;
		SymbolTable symbolTable = program.getSymbolTable();
		SymbolIterator symbolIterator = symbolTable.getAllSymbols(true);

		try (PrintWriter writer = new PrintWriter(new FileOutputStream(file))) {
			while (symbolIterator.hasNext()) {
				try {
					monitor.checkCancelled();
				} catch (CancelledException e) {
					throw new ExporterException(e);
				}
				
				Symbol symbol = symbolIterator.next();
				writer.println(symToMap(symbol));
			}
		}

		return true;
	}

	protected String symToMap(Symbol s) {
		return String.format("%s ? %s", s.getAddress().toString(), s.getName());
	}
}
