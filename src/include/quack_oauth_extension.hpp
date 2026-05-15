#pragma once

#include "duckdb/main/extension.hpp"

namespace duckdb {

class ExtensionLoader;

class QuackOauthExtension : public Extension {
public:
	void Load(ExtensionLoader &db) override;
	string Name() override;
	string Version() const override;
};

} // namespace duckdb
