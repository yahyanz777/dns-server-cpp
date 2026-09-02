#pragma once

#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

class CSVReader
{
public:
    explicit CSVReader(const std::string& filename)
    {
        file_.open(filename);

        if (!file_.is_open())
        {
            throw std::runtime_error(
                "Failed to open CSV file: " + filename
            );
        }
    }

    ~CSVReader()
    {
        if (file_.is_open())
            file_.close();
    }

    inline bool readRow(std::vector<std::string>& row)
    {
        row.clear();

        std::string line;

        if (!std::getline(file_, line))
            return false;

        std::stringstream ss(line);
        std::string field;

        while (std::getline(ss, field, ','))
        {
            row.push_back(field);
        }

        return true;
    }

private:
    std::ifstream file_;
};