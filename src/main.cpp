#include <stdio.h>
#include <fstream>
#include <tinyxml2.h>
#include <regex>
#include <cctype>
#include <string>
#include <algorithm>
#include <cassert>
#include <set>
#include <memory>
#include <vector>
#include <list>
#include <map>

#if __GNUC__ < 5
	#error Use a less ancient compiler. God damn.
#endif

using namespace tinyxml2;

struct Segment;

struct Instr
{
	uint32_t addr;
	std::string bytes;
	std::string op;
	std::string arg1;
	std::string arg2;

	bool branch;
	bool unc_branch; // unconditional branch

	uint32_t idx;
	Segment* segment;
	typedef std::shared_ptr<Instr> ptr;
};

struct Segment
{
	uint32_t addr_start;
	uint32_t addr_end;

	std::vector<Segment*> branch_to; // at most two branches out

	std::vector<Instr*> insts;
	typedef std::shared_ptr<Segment> ptr;

	void link_to(Segment* to)
	{
		if(!to)
			return;

		branch_to.push_back(to);
	}
};

struct Sub
{
	uint32_t addr_start;
	uint32_t addr_end;

	std::vector<Segment::ptr> segments;
	typedef std::shared_ptr<Sub> ptr;
};

struct Instr_Q_Data
{
	Instr* c_inst;
	Sub::ptr c_sub;
	Segment::ptr c_segment;
	Segment::ptr c_from_segment;

	typedef std::shared_ptr<Instr_Q_Data> ptr;
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

void process_inst(std::vector<Instr>& insts, std::list<Instr_Q_Data::ptr>& insts_queue)
{
	Instr_Q_Data::ptr inst_data = insts_queue.back();
	insts_queue.pop_back();

	Instr* c_inst = inst_data->c_inst;
	Sub::ptr c_sub = inst_data->c_sub;
	Segment::ptr c_segment = inst_data->c_segment;

	if(c_inst->segment)
	{
		if(c_inst->segment->addr_start != c_inst->addr)
		{
			// Split
			Segment::ptr n_segment = Segment::ptr(new Segment);
			Segment* o_segment = c_inst->segment;
			n_segment->addr_start = c_inst->addr;
			n_segment->addr_end = o_segment->addr_end;

			std::vector<Instr*> insts_copy = o_segment->insts;
			o_segment->insts.clear();

			auto n_start = std::find(insts_copy.begin(), insts_copy.end(), c_inst);
			auto n_end = n_start - 1;
			o_segment->addr_end = (*n_end)->addr;

			o_segment->insts = std::vector<Instr*>(insts_copy.begin(), n_start);
			n_segment->insts = std::vector<Instr*>(n_start, insts_copy.end());

			for(auto t_inst : n_segment->insts)
			{
				t_inst->segment = n_segment.get();
			}

			// set the branching
			n_segment->branch_to = o_segment->branch_to;
			o_segment->branch_to.clear();

			o_segment->link_to(n_segment.get());
			if(inst_data->c_from_segment.get() == o_segment)
			{
				// self loop
				if(c_segment.get() == nullptr)
				{
					n_segment->link_to(n_segment.get());
				}
			}
			else
			{
				inst_data->c_from_segment->link_to(n_segment.get());
			}

			c_sub->segments.push_back(n_segment);

			// go through the queue and fix up pointers
			for(auto qdata : insts_queue)
			{
				if(qdata->c_from_segment.get() == o_segment)
				{
					qdata->c_from_segment = n_segment;
					printf("fix up\n");
				}
			}
		}
		else
		{
			if(inst_data->c_from_segment.get())
			{
				inst_data->c_from_segment->link_to(c_inst->segment);
			}
		}
		return;
	}

	uint32_t addr = c_inst->addr;
	c_sub->addr_end = addr;

	if(c_segment.get() == nullptr || c_sub->segments.empty())
	{
		printf("New segment\n");
		c_sub->segments.push_back(Segment::ptr(new Segment));
		c_segment = c_sub->segments.back();
		c_segment->addr_start = addr;

		if(inst_data->c_from_segment.get())
		{
			inst_data->c_from_segment->link_to(c_segment.get());
		}
	}
	c_segment->addr_end = addr;

	c_inst->segment = c_segment.get();
	c_segment->insts.push_back(c_inst);
	bool has_branch = false;
	bool no_link_to_next = false;
	if(c_inst->branch)
	{
		uint32_t b_addr = 0;

		if(c_inst->op == "bf" || c_inst->op == "br")
			b_addr = strtoul(c_inst->arg2.c_str() + 3, nullptr, 16);
		else
			b_addr = strtoul(c_inst->arg1.c_str() + 3, nullptr, 16);

		if(b_addr)
		{
			has_branch = true;

			for(auto& t_inst : insts)
			{
				if(t_inst.addr == b_addr)
				{
					printf(" Branch addr : %08X\n", b_addr);
					Instr_Q_Data* nq_data = new Instr_Q_Data;
					nq_data->c_inst = &t_inst;
					nq_data->c_sub = c_sub;
					nq_data->c_from_segment = c_segment;

					if(c_inst->unc_branch)
						no_link_to_next = true;

					insts_queue.push_back(Instr_Q_Data::ptr(nq_data));
					break;
				}
			}
		}
	}

	if(!no_link_to_next && (c_inst->idx + 1) < insts.size())
	{
		if(insts[c_inst->idx + 1].op != "ret")
		{
			Instr_Q_Data* nq_data = new Instr_Q_Data;
			nq_data->c_inst = &insts[c_inst->idx + 1];
			if(!has_branch)
			{
				nq_data->c_segment = c_segment;
			}
			nq_data->c_from_segment = c_segment;
			nq_data->c_sub = c_sub;
			insts_queue.push_back(Instr_Q_Data::ptr(nq_data));
		}
		else
		{
			c_inst = &insts[c_inst->idx + 1];
			c_segment->addr_end = c_inst->addr;
			c_segment->insts.push_back(c_inst);
		}
	}
}

int main(int argc, char **argv)
{
	if(argc < 3)
	{
		printf("usage: %s [fw filename] [out filename]\n", argv[0]);
		return 0;
	}

	std::string out_fname = argv[2];

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
		vertical-align: top;\
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
		height: 2em;\
	}\
	.branch\
	{\
		color: purple;\
	}\
	.branch-target\
	{\
		color: orange;\
	}\
	a, a:visited, a:hover, a:active \
	{\
  		color: inherit;\
  		text-decoration: none;\
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

	std::vector<Sub::ptr> subs;
	std::string s;

	std::regex oda_regex("^\\s+.data:([0-9A-Fa-f]+)\\s+([0-9A-Fa-f\\s]{2,32})\\s+([A-Za-z0-9]+)(?:\\s([^,]+))?(?:,\\s*(.+))?");
	std::regex objdump_regex("^ +(\\w+):\\t([\\w ]+)\\t([\\w]+)(?:\\s([^,]+))?(?:,\\s*(.+))?");

	bool picked = false;
	std::regex r;

	while(std::getline(f, s))
	{
		// *shakes fist at whoever decided crlf newlines were a good idea*
		if(s.substr(s.length()-1, 1) == "\r")
		{
			s = s.substr(0, s.length()-1);
		}

		if(!picked)
		{
			if(s.find(".data") != std::string::npos)
			{
				r = oda_regex;
			}
			else
			{
				r = objdump_regex;
			}

			picked = true;
		}

		std::smatch m;
		if(std::regex_match(s, m, r))
		{
			std::string addr_s = "0x" + trim(m[1].str());
			uint32_t addr = strtoul(addr_s.c_str(), nullptr, 16);
			std::string bytes = trim(m[2].str());
			std::string op =    trim(m[3].str());
			std::string arg1 =  trim(m[4].str());
			std::string arg2 =  trim(m[5].str());

			instrs.push_back(Instr {addr, bytes, op, arg1, arg2, false, false, (uint32_t)instrs.size()});

			if(subs.empty())
			{
				subs.push_back(Sub::ptr(new Sub));
				subs.back()->addr_start = addr;
			}

			if(op == "call")
			{
				if(strip_arg(arg1))
				{
					uint32_t t = strtoul(arg1.c_str(), nullptr, 16);
					xrefs[addr]["call"] = t;

					if(rev_xrefs.find(t) == rev_xrefs.end())
					{
						rev_xrefs[t] = std::map<std::string, std::set<int>>();

						subs.push_back(Sub::ptr(new Sub));
						subs.back()->addr_start = t;
					}
					rev_xrefs[t]["call"].insert(addr);
				}
			}
			else if(op == "br" || op == "bz" || op == "bnz" || op == "bt" || op == "bf"
			|| op == "bh" || op == "bnh" || op == "bc" || op == "bnc")
			{
				instrs.back().branch = true;
				if(op == "br")
					instrs.back().unc_branch = true;

				std::string &arg = (arg2 != "") ? arg2 : arg1;
				if(strip_arg(arg))
				{
					int t = strtoul(arg.c_str(), nullptr, 16);
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

	bool opt_argTd = true;
	bool opt_bytes = true;

	for(auto instr : instrs)
	{
		XMLElement *line = doc.NewElement("tr");
		line->SetAttribute("id", std::to_string(instr.addr).c_str());
		line->SetAttribute("class", "line");

		std::string a = string_sprintf("%08x", instr.addr);
		XMLElement *line_addr = col(doc, a, "addr");
		//line->InsertAfterChild(line_anchor, line_addr);
		line->InsertFirstChild(line_addr);

		if(opt_bytes)
		{
			XMLElement *line_bytes = col(doc, instr.bytes, "bytes");
			line->InsertEndChild(line_bytes);
		}

		XMLElement *line_op = doc.NewElement("td");
		line_op->SetAttribute("class", "pre");
		XMLElement *line_op_span = span(doc, instr.op, "op");
		line->InsertEndChild(line_op);
		line_op->InsertFirstChild(line_op_span);

		XMLElement *line_arg1 = nullptr;
		XMLElement *line_arg2 = nullptr;

		if(instr.arg1 != "")
		{
			XMLText *space = doc.NewText(", ");
			line_arg1 = span(doc, instr.arg1, "arg1");

			XMLElement *arg_td;
			if(opt_argTd)
			{
				arg_td = doc.NewElement("td");
				arg_td->InsertFirstChild(line_arg1);
				line->InsertEndChild(arg_td);
			}
			else
			{
				line_op->InsertEndChild(line_arg1);
			}

			if(instr.arg2 != "")
			{
				line_arg2 = span(doc, instr.arg2, "arg2");
				if(opt_argTd)
				{
					arg_td->InsertEndChild(space);
					arg_td->InsertEndChild(line_arg2);
				}
				else
				{
					line_op->InsertEndChild(space);
					line_op->InsertEndChild(line_arg2);
				}
			}
		}

		std::string xref_link;

		if(xrefs.find(instr.addr) != xrefs.end())
		{
			// dubious af code
			std::string info = "{";
			for(auto pair : xrefs[instr.addr])
			{
				info += "\"" + pair.first + "\" : ";
				info += std::to_string(pair.second);
				xref_link = "#" + std::to_string(pair.second);
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

		if(xref_link == "")
		{
			table->InsertEndChild(line);
		}
		else
		{
			XMLElement *a = line_arg1;
			if(instr.op == "bf" || instr.op == "bt")
			{
				a = line_arg2;
			}
			a->SetName("a");
			a->SetAttribute("href", xref_link.c_str());

			table->InsertEndChild(line);
		}
	}
	doc.SaveFile(out_fname.c_str());

	for(auto sub : subs)
	{
		printf("Sub : 0x%04x\n", sub->addr_start);
		fflush(stdout);

		std::list<Instr_Q_Data::ptr> insts_queue;

		auto res = std::find_if(instrs.begin(), instrs.end(), [sub](const Instr& instr){
			return instr.addr == sub->addr_start;
		});

		if(res != instrs.end())
		{
			Instr_Q_Data* nq_data = new Instr_Q_Data;
			nq_data->c_inst = &*res;
			nq_data->c_sub = sub;

			insts_queue.push_back(Instr_Q_Data::ptr(nq_data));
			while(!insts_queue.empty())
			{
				process_inst(instrs, insts_queue);
			}

			char tfname[0x100];
			sprintf(tfname, "0x%04x.dot", sub->addr_start);

			FILE* dotfile = fopen(tfname, "w+b");
			fprintf(dotfile, "digraph name {\n");
			fprintf(dotfile, "\tgraph [fontname = \"courier\"];\n");
			fprintf(dotfile, "\tnode [fontname = \"courier\"];\n");
			fprintf(dotfile, "\tedge [fontname = \"courier\"];\n");
			for(auto s : sub->segments)
			{
				fprintf(dotfile, "\tf%04x[label=\"{0x%04x|", s->addr_start, s->addr_start);

				for(auto insts : s->insts)
				{
					fprintf(dotfile, "%s %s%s%s\\l", insts->op.c_str(), insts->arg1.c_str(), insts->arg2.length() ? ", " : "", insts->arg2.c_str());
				}

				fprintf(dotfile, "}\" shape=record]\n");
				for(auto bst : s->branch_to)
				{
					fprintf(dotfile, "\tf%04x -> f%04x\n", s->addr_start, bst->addr_start);
				}
			}
			fprintf(dotfile, "}\n");
			fclose(dotfile);

			// Clean up
			for(auto segment : sub->segments)
			{
				for(auto inst : segment->insts)
				{
					inst->segment = nullptr;
				}
			}
		}
	}
}
