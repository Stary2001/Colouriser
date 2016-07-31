#include <stdio.h>
#include <fstream>
#include <tinyxml2.h>
#include <regex>
#include <cctype>
#include <string>
#include <algorithm>
#include <cassert>
#include <set>

using namespace tinyxml2;

struct Instr
{
	int addr;
	std::string bytes;
	std::string op;
	std::string arg1;
	std::string arg2;

	bool branch;
};

// http://stackoverflow.com/questions/216823/whats-the-best-way-to-trim-stdstring

inline std::string trim(const std::string &s)
{
   auto wsfront=std::find_if_not(s.begin(),s.end(),[](int c){return std::isspace(c);});
   auto wsback=std::find_if_not(s.rbegin(),s.rend(),[](int c){return std::isspace(c);}).base();
   return (wsback<=wsfront ? std::string() : std::string(wsfront,wsback));
}

template< typename... Args >
std::string string_sprintf( const char* format, Args... args ) {
  int length = std::snprintf( nullptr, 0, format, args... );
  assert( length >= 0 );

  char* buf = new char[length + 1];
  std::snprintf( buf, length + 1, format, args... );

  std::string str( buf );
  delete[] buf;
  return std::move(str);
}

XMLElement *span(XMLDocument &d, std::string &text, std::string classname)
{
	std::string c = classname + " pre";

	XMLElement *span = d.NewElement("span");
	span->SetAttribute("class", c.c_str());
	XMLText *span_text = d.NewText(text.c_str());
	span->InsertFirstChild(span_text);

	return span;
}

XMLElement *col(XMLDocument &d, std::string &text, std::string classname)
{
	std::string c = classname + " pre";

	XMLElement *td = d.NewElement("td");
	td->SetAttribute("class", c.c_str());
	XMLText *td_text = d.NewText(text.c_str());
	td->InsertFirstChild(td_text);

	return td;
}

void add_class(XMLElement *e, std::string to_add)
{
	const char *klass = e->Attribute("class");
	std::string curclass;
	if(klass != nullptr)
	{
		curclass = klass;
		curclass += " ";
	}
	curclass += to_add;
	e->SetAttribute("class", curclass.c_str());
}

bool strip_arg(std::string &arg)
{
	bool imm = false;
	while(true)
	{
		if(arg.substr(0,1) == "!" || arg.substr(0, 1) == "$")
		{
			imm = true;
			arg = arg.substr(1);
		}
		else
		{
			break;
		}
	}
	return imm;
}

int main(int argc, char **argv)
{
	if(argc < 3)
	{
		printf("usage: %s [fw filename] [out filename]\n", argv[0]);
		return 1;
	}

	std::regex r("^\\s+.data:([0-9A-Fa-f]+)\\s+([0-9A-Fa-f\\s]{2,32})\\s+([A-Za-z0-9]+)(?:\\s([^,]+))?(?:,\\s*(.+))?");
	std::ifstream f(argv[1]);
	if(!f.good())
	{
		fprintf(stderr, "could not open file '%s'\n", argv[1]);
		return 1;
	}

	XMLDocument doc;
	XMLElement *root = doc.NewElement("html");
	doc.InsertFirstChild(root);
	XMLElement *head = doc.NewElement("head");
	root->InsertFirstChild(head);
	XMLElement *title = doc.NewElement("title");
	XMLText *title_text = doc.NewText("I Can't Believe It's Not IDA!");
	title->InsertFirstChild(title_text);
	head->InsertFirstChild(title);

	std::string css = ".pre \
	{\
		font-family: monospace;\
		padding-top: 0;\
		padding-bottom: 0;\
	}\
	.callee\
	{\
		color: red;\
	}\
	.call\
	{\
		color: blue;\
	}\
	.ret\
	{\
		color: green;\
	}\
	.branch\
	{\
		color: purple;\
	}\
	.branch-target\
	{\
		color: orange;\
	}\
	";

	XMLElement *style = doc.NewElement("style");
	XMLText *style_text = doc.NewText(css.c_str());
	style->InsertFirstChild(style_text);
	head->InsertAfterChild(title, style);

	XMLElement *body = doc.NewElement("body");
	root->InsertAfterChild(head, body);

	XMLElement *table = doc.NewElement("table");
	body->InsertFirstChild(table);

	std::vector<Instr> instrs;
	std::map<int, std::map<std::string, int>> xrefs;
	std::map<int, std::map<std::string, std::set<int>>> rev_xrefs;

	std::string s;
	while(std::getline(f, s))
	{
		std::smatch m; 
		if(std::regex_match(s, m, r))
		{
			std::string addr_s = "0x" + trim(m[1].str());
			int addr = strtoul(addr_s.c_str(), nullptr, 16);
			std::string bytes = trim(m[2].str());
			std::string op =    trim(m[3].str());
			std::string arg1 =  trim(m[4].str());
			std::string arg2 =  trim(m[5].str());

			instrs.push_back(Instr {addr, bytes, op, arg1, arg2});
			if(op == "call")
			{
				if(strip_arg(arg1))
				{
					int t = strtoul(arg1.c_str(), nullptr, 16);
					xrefs[addr]["call"] = t;

					if(rev_xrefs.find(t) == rev_xrefs.end())
					{
						rev_xrefs[t] = std::map<std::string, std::set<int>>();
					}
					rev_xrefs[t]["call"].insert(addr);
				}
			}
			else if(op == "br" || op == "bz" || op == "bnz" || op == "bt" || op == "bf")
			{
				instrs.back().branch = true;

				std::string &arg = (arg2 != "") ? arg2 : arg1;
				if(strip_arg(arg))
				{
					int t = strtoul(arg1.c_str(), nullptr, 16);
					xrefs[addr]["branch"] = t;
					if(rev_xrefs.find(t) == rev_xrefs.end())
					{
						rev_xrefs[t] = std::map<std::string, std::set<int>>();
					}
					rev_xrefs[t]["branch"].insert(addr);
				}
			}
		}
	}

	for(auto instr : instrs)
	{
		/*XMLText *space1 = doc.NewText(" ");
		XMLText *space2 = doc.NewText(" ");
		XMLText *space3 = doc.NewText(" ");
		XMLText *space4 = doc.NewText(", ");*/
		XMLElement *line = doc.NewElement("tr");
		line->SetAttribute("class", "line");

		/*XMLElement *line_anchor = doc.NewElement("a");
		line_anchor->SetAttribute("name", addr.c_str());
		XMLText *fuck_you_html = doc.NewText("");
		line_anchor->InsertFirstChild(fuck_you_html);
		line->InsertFirstChild(line_anchor);*/

		std::string a = string_sprintf("%08x", instr.addr);
		XMLElement *line_addr = col(doc, a, "addr");
		//line->InsertAfterChild(line_anchor, line_addr);
		line->InsertFirstChild(line_addr);

		XMLElement *line_bytes = col(doc, instr.bytes, "bytes");
		line->InsertAfterChild(line_addr, line_bytes);

		XMLElement *line_op = doc.NewElement("td");
		line_op->SetAttribute("class", "pre");
		XMLElement *line_op_span = span(doc, instr.op, "op");
		line->InsertAfterChild(line_bytes, line_op);
		line_op->InsertFirstChild(line_op_span);

		if(instr.arg1 != "")
		{
			XMLText *space = doc.NewText(", ");
			XMLElement *line_arg1 = span(doc, instr.arg1, "arg1");
			line_op->InsertAfterChild(line_op_span, line_arg1);

			if(instr.arg2 != "")
			{
				line_op->InsertAfterChild(line_arg1, space);
				XMLElement *line_arg2 = span(doc, instr.arg2, "arg2");
				line_op->InsertAfterChild(space, line_arg2);
			}
		}

		if(xrefs.find(instr.addr) != xrefs.end())
		{
			std::string info = "{";
			for(auto pair : xrefs[instr.addr])
			{
				info += "\"" + pair.first + "\" : ";
				info += std::to_string(pair.second);
			}
			info += "}";

			if(instr.branch)
			{
				add_class(line, "branch");
			}
			else
			{
				add_class(line, "call");
			}
			
			line->SetAttribute("data-xref-info", info.c_str());
		}
		
		// no we can't use auto here. :(
		std::map<int, std::map<std::string, std::set<int>>>::iterator rev_xref_it;
		if((rev_xref_it = rev_xrefs.find(instr.addr)) != rev_xrefs.end())
		{
			if(rev_xref_it->second.find("call") != rev_xref_it->second.end())
			{
				add_class(line, "callee");
			}
			else if(rev_xref_it->second.find("branch") != rev_xref_it->second.end())
			{
				add_class(line, "branch-target");
			}

			std::string info = "{";

			for(auto pair : rev_xrefs[instr.addr])
			{
				info += "\"" + pair.first + "\" : [";
				for(auto a : pair.second)
				{
					info += std::to_string(a) + ", ";
				}
				info = info.substr(0, info.length()-2);
				info += "], ";
			}
			info = info.substr(0, info.length()-2);
			info += "}";

			line->SetAttribute("data-rev-xref-info", info.c_str());
		}

		if(instr.branch)
		{
			add_class(line, "branch");
		}

		if(instr.op == "ret")
		{
			add_class(line, "ret");
		}

		table->InsertEndChild(line);
		/*XMLElement *br = doc.NewElement("br");
		body->InsertEndChild(br);*/
	}

	doc.SaveFile(argv[2]);
}